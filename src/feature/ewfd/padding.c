#include "feature/ewfd/padding.h"
#include "circpad_negotiation.h"
#include "circpad_negotiation.h"
#include <stdint.h>
#include <stdbool.h>
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "core/or/circuitpadding.h"
#include "feature/ewfd/utils.h"

/**
协议：
1. 通过CIRCPAD_COMMAND_EWFD_DATA来同步padding units配置，指定当前circ需要使用的padding unit，
	让relay去下载或者同步这些需要padding units。
2. 
*/

// eBPF code list
smartlist_t *client_unit_confs = NULL;

// padding unit的内存由circ管理，在circ关闭时一起关
static int padding_units_num = 0;
static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_conf_st *conf, uint32_t unit_version);
static void free_ewfd_padding_unit(ewfd_padding_unit_st *unit);
static bool ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid);
static int free_ewfd_padding_unit_by_uuid(circuit_t *circ, int unit_uuid, uint32_t unit_version);

void ewfd_padding_init() {
	EWFD_LOG("ewfd_padding_init");
	client_unit_confs = smartlist_new();
	ewfd_padding_conf_st *st_test = tor_malloc_zero(sizeof(ewfd_padding_conf_st));
	st_test->unit_slot = 0;
	st_test->unit_uuid = 1;
	st_test->target_hopnum = 2;
	st_test->deploy_hop = EWFD_NODE_ROLE_CLIENT; // client only
	smartlist_add(client_unit_confs, st_test);
}

void ewfd_padding_free() {
	EWFD_LOG("ewfd_padding_free");
	if (client_unit_confs != NULL) {
		SMARTLIST_FOREACH(client_unit_confs,
			circpad_machine_spec_t *,
			conf, tor_free(conf));
		smartlist_free(client_unit_confs);
	}
}

/** STEP-1: Origin(client) add padding unit, and send negotiate commands to OR
* unit_version: 用于判断某个slot的unit是否一致，增加一个Unit之后，version + 1 = machine_ctr
* neogation -> machine_ctr (发送增加之后的machine_tr)
*/
int add_ewfd_units_on_circ(circuit_t *circ) {
	if (client_unit_confs == NULL) return 0;
	if (!CIRCUIT_IS_ORIGIN(circ)) {
		return 0;
	}
	origin_circuit_t *on_circ = TO_ORIGIN_CIRCUIT(circ);
	if (on_circ->padding_negotiation_failed) {
		return 0;
	}

	int current_role = ewfd_get_node_role_for_circ(circ);

	// 初始化所有的padding machine
	SMARTLIST_FOREACH_BEGIN(client_unit_confs, ewfd_padding_conf_st *, conf) {
		if (!(conf->deploy_hop & current_role)) {
			continue;
		}
		// add or replace a slot
		int slot = conf->unit_slot;
		if (circ->ewfd_padding_unit[slot] == NULL) {
			ewfd_add_unit_to_circ_by_uuid(circ, conf->unit_uuid);

			EWFD_LOG("STEP-1: Notify hop: %d to init unit uuid:%u version:%u on circ: %u", conf->target_hopnum, conf->unit_uuid,
				circ->padding_machine_ctr, on_circ->global_identifier);
			// 通知relay开启对应的padding unit
			// machine_ctr，unit版本号 = 当前machine num
			if (circpad_negotiate_padding(TO_ORIGIN_CIRCUIT(circ), conf->unit_uuid,
			conf->target_hopnum,
			CIRCPAD_COMMAND_EWFD_START,
			circ->padding_machine_ctr) < 0) {
				EWFD_LOG("Faild to notify relay to init padding unit: %d %u", slot, conf->unit_uuid);
				// on_circ->padding_negotiation_failed = 1;
				tor_free(circ->ewfd_padding_unit[slot]);
				circ->ewfd_padding_unit[slot] = NULL;
			}
		} else {
			EWFD_LOG("Unit: %u already exists in Slot: %u. Ingore.", conf->unit_uuid, conf->unit_slot);
		}
		
	} SMARTLIST_FOREACH_END(conf);
	
	return 0;
}

void free_all_ewfd_units_on_circ(circuit_t *circ) {
	int cid = CIRCUIT_IS_ORIGIN(circ) ? TO_ORIGIN_CIRCUIT(circ)->global_identifier : -1;
	int free_num = 0;
	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
		if (circ->ewfd_padding_unit[i] != NULL) {
			free_ewfd_padding_unit(circ->ewfd_padding_unit[i]);
			circ->ewfd_padding_unit[i] = NULL;
			free_num++;
		}
	}
	if (free_num > 0) {
		EWFD_LOG("Step-n: Free %d/%u eWFD units on circ: %d remain: %d", free_num, circ->padding_machine_ctr, cid, padding_units_num);
	}
}

/** STEP-2: OR handle padding negotiate
* set 
*/
int ewfd_handle_padding_negotiate(circuit_t *circ, circpad_negotiate_t *negotiate) {
	int retval = 0;
	bool should_response = true;
	EWFD_LOG("STEP-2: handle negotiate: %d uuid:%u version:%u", negotiate->command, negotiate->machine_type, negotiate->machine_ctr);
	if (negotiate->command == CIRCPAD_COMMAND_EWFD_START) {
		if (ewfd_add_unit_to_circ_by_uuid(circ, negotiate->machine_type)) {
			if (negotiate->machine_ctr && circ->padding_machine_ctr != negotiate->machine_ctr) {
				EWFD_LOG("WARN: Client and relay have different counts of padding units: "
					"%u vs %u", circ->padding_machine_ctr, negotiate->machine_ctr);
			}
			circpad_cell_event_nonpadding_received(circ);
		} else {
			retval = -1;
		}
	}
	else if (negotiate->command == CIRCPAD_COMMAND_EWFD_STOP) {
		if (free_ewfd_padding_unit_by_uuid(circ, negotiate->machine_type, negotiate->machine_ctr)) {
			EWFD_LOG("OR stop padding unit: %d", negotiate->machine_type);
			circpad_padding_negotiated(circ, negotiate->machine_type,
				negotiate->command, CIRCPAD_RESPONSE_OK,
				negotiate->machine_ctr);
		} else {
			should_response = false;
			if (negotiate->machine_ctr <= circ->padding_machine_ctr) {
				EWFD_LOG("OR stop old padding unit: %u %u", negotiate->machine_type, negotiate->machine_ctr);
			} else {
				EWFD_LOG("WARN: OR stop unkown padding unit: %u %u", negotiate->machine_type, negotiate->machine_ctr);
				retval = -1;
			}
		}
	} 
	else if (negotiate->command == CIRCPAD_COMMAND_EWFD_DATA) {
		// 传输eWFD插件
	}

	if (should_response) {
		circpad_padding_negotiated(circ, negotiate->machine_type,
				negotiate->command,
				(retval == 0) ? CIRCPAD_RESPONSE_OK : CIRCPAD_RESPONSE_ERR,
				negotiate->machine_ctr);
	}

	circpad_negotiate_free(negotiate);
	return retval;
}

/** STEP-3: OR handle padding negotiated
* 
*/
int ewfd_handle_padding_negotiated(circuit_t *circ, circpad_negotiated_t *negotiated) {
	EWFD_LOG("STEP-3: handle negotiated: %d uuid:%u version:%u", negotiated->command, negotiated->machine_type, negotiated->machine_ctr);
	if (negotiated->command == CIRCPAD_COMMAND_EWFD_STOP) {
		EWFD_LOG("Received STOP command on PADDING_NEGOTIATED for circuit %u",
			TO_ORIGIN_CIRCUIT(circ)->global_identifier);
		free_ewfd_padding_unit_by_uuid(circ, negotiated->machine_type, negotiated->machine_ctr);
	} else if (negotiated->command == CIRCPAD_COMMAND_EWFD_START) {
		if (negotiated->response == CIRCPAD_RESPONSE_ERR) {
			// 如果Machine存在了就释放，并报错
			if (free_ewfd_padding_unit_by_uuid(circ, negotiated->machine_type, negotiated->machine_ctr)) {
				TO_ORIGIN_CIRCUIT(circ)->padding_negotiation_failed = 1;
				EWFD_LOG("ERROR: Middle node did not accept our padding request on circuit "
					"%u (%d)", TO_ORIGIN_CIRCUIT(circ)->global_identifier, circ->purpose);
			}
		} else {
			EWFD_LOG("Seuccess to init EWFD Padding Unit on this node uuid:%u version:%u", negotiated->machine_type, negotiated->machine_ctr);
		}
		
	}

	circpad_negotiated_free(negotiated);
	return 0;
}

/*
1. 判断方向
Client(ORIGIN) -> OR
OR -> Client: 只处理CELL_DIRECTION_IN的包（moving towards the origin）
OR -> OR: CELL_DIRECTION_OUT忽略
*/
int trigger_ewfd_units_on_circ(circuit_t *circ, bool is_send, bool toward_origin) {
	if (client_unit_confs == NULL) return 0;
	bool is_origin = CIRCUIT_IS_ORIGIN(circ);

	// no padding units on circ
	if (circ->padding_machine_ctr == 0) {
		return 0;
	}
	
	// Client -> OR 
	if (is_origin && is_send) {
		EWFD_LOG("trigger_ewfd_units_on_circ Client -> OR ");
	}

	// OR -> Client
	if (!is_origin && toward_origin) {
		EWFD_LOG("trigger_ewfd_units_on_circ OR -> Client ");
	}

	// timer 触发
	return 0;
}


/** ----------------------------------------------------------
	Private Functions
*/
static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_conf_st *conf, uint32_t unit_version) {
	ewfd_padding_unit_st *unit = tor_malloc_zero(sizeof(ewfd_padding_unit_st));
	unit->conf = conf;
	unit->unit_version = unit_version;
	padding_units_num++;
	return unit;
}

static void free_ewfd_padding_unit(ewfd_padding_unit_st *unit) {
	padding_units_num--;
	tor_free(unit);
}

// 根据收到的unit type，找到已有的padding unit，到or_circ
static bool ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid) {
	ewfd_padding_conf_st *target_conf = NULL;
	tor_assert(client_unit_confs);
	SMARTLIST_FOREACH_BEGIN(client_unit_confs, ewfd_padding_conf_st *, conf) {
		if (conf->unit_uuid == unit_uuid) {
			target_conf = conf;
			break;
		}
	} SMARTLIST_FOREACH_END(conf);

	if (target_conf == NULL) {
		EWFD_LOG("ERROR: padding unit not found: %u", unit_uuid);
		return false;
	}

	int slot = target_conf->unit_slot;

	if (circ->ewfd_padding_unit[slot] != NULL) {
		free_ewfd_padding_unit_by_uuid(circ, unit_uuid, circ->padding_machine_ctr);
		EWFD_LOG("Unit already exists. Replace. Slot: %u uuid: %d", slot, unit_uuid);
		tor_free(circ->ewfd_padding_unit[slot]);
		circ->ewfd_padding_unit[slot] = NULL;
	}

	circ->ewfd_padding_unit[slot] = new_ewfd_padding_unit(target_conf, circ->padding_machine_ctr);

	// increase padding machine counter
	circ->padding_machine_ctr++;
	if (circ->padding_machine_ctr == 0) {
		circ->padding_machine_ctr = 1;
	}

	if (CIRCUIT_IS_ORIGIN(circ)) {
		EWFD_LOG("Unit: %u is added to client/origin_circ: %d", unit_uuid, TO_ORIGIN_CIRCUIT(circ)->global_identifier);
	} else {
		EWFD_LOG("Unit: %u is added to relay/or_circ peer: %s", unit_uuid, ewfd_get_circuit_info(circ));
	}

	return true;
}

static int free_ewfd_padding_unit_by_uuid(circuit_t *circ, int unit_uuid, uint32_t unit_version) {
	int found = 0;

	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
		if (circ->ewfd_padding_unit[i] && circ->ewfd_padding_unit[i]->conf->unit_uuid == unit_uuid) {
			if (circ->padding_machine_ctr == unit_version) {
				free_ewfd_padding_unit(circ->ewfd_padding_unit[i]);
				circ->ewfd_padding_unit[i] = NULL;
				found = 1;
			} else {
				EWFD_LOG("EWFD: padding shutdown for wrong (old?) machine ctr: %u vs %u",
					unit_version, circ->padding_machine_ctr);
			}
		}
	}
	return found;
}
