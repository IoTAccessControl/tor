#include "feature/ewfd/padding.h"
#include "circpad_negotiation.h"
#include "feature/ewfd/debug.h"
#include <stdint.h>
#include <stdbool.h>
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "core/or/circuitpadding.h"


/**
协议：
1. 通过CIRCPAD_COMMAND_EWFD_DATA来同步padding units配置，指定当前circ需要使用的padding unit，
	让relay去下载或者同步这些需要padding units。
2. 
*/

// eBPF code list
smartlist_t *client_unit_confs = NULL;

static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_conf_st *conf, uint32_t unit_version);
static int free_ewfd_padding_unit(circuit_t *circ, int unit_uuid, uint32_t unit_version);
static bool ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid);

void ewfd_padding_init() {
	EWFD_LOG("ewfd_padding_init");
	client_unit_confs = smartlist_new();
	ewfd_padding_conf_st *st_test = tor_malloc_zero(sizeof(ewfd_padding_conf_st));
	st_test->unit_slot = 0;
	st_test->unit_uuid = 1;
	st_test->target_hopnum = 1;
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
	if (!CIRCUIT_IS_ORIGIN(circ)) {
		return 0;
	}
	origin_circuit_t *on_circ = TO_ORIGIN_CIRCUIT(circ);
	if (on_circ->padding_negotiation_failed) {
		return 0;
	}
	return 0;

	// 初始化所有的padding machine
	SMARTLIST_FOREACH_BEGIN(client_unit_confs, ewfd_padding_conf_st *, conf) {
		// add or replace a slot
		int slot = conf->unit_uuid;
		if (circ->ewfd_padding_unit[slot] == NULL) {
			ewfd_add_unit_to_circ_by_uuid(circ, conf->unit_uuid);

			// 通知relay开启对应的padding unit
			if (circpad_negotiate_padding(TO_ORIGIN_CIRCUIT(circ), slot,
			conf->target_hopnum,
			CIRCPAD_COMMAND_EWFD_START,
			circ->padding_machine_ctr) < 0) {
				EWFD_LOG("Faild to notify relay to init padding unit: %d %u", slot, conf->unit_uuid);
				on_circ->padding_negotiation_failed = 1;
				tor_free(circ->ewfd_padding_unit[slot]);
				circ->ewfd_padding_unit[slot] = NULL;
			}
		} else {
			EWFD_LOG("Unit: %u already exists. Ingore.", conf->unit_uuid);
		}
		
	} SMARTLIST_FOREACH_END(conf);
	
	return 0;
}

/** STEP-2: OR handle padding negotiate
* set 
*/
int ewfd_handle_padding_negotiate(circuit_t *circ, circpad_negotiate_t *negotiate) {
	if (negotiate->command == CIRCPAD_COMMAND_EWFD_START) {
		if (ewfd_add_unit_to_circ_by_uuid(circ, negotiate->machine_type)) {
			if (negotiate->machine_ctr && circ->padding_machine_ctr != negotiate->machine_ctr) {
				EWFD_LOG("WARN: Client and relay have different counts of padding units: "
					"%u vs %u", circ->padding_machine_ctr, negotiate->machine_ctr);
			}
			circpad_cell_event_nonpadding_received(circ);
		}
		return 0;
	} 
	else if (negotiate->command == CIRCPAD_COMMAND_EWFD_STOP) {
		if (free_ewfd_padding_unit(circ, negotiate->machine_type, negotiate->machine_ctr)) {
			EWFD_LOG("OR stop padding unit: %d", negotiate->machine_type);
			circpad_padding_negotiated(circ, negotiate->machine_type,
				negotiate->command, CIRCPAD_RESPONSE_OK,
				negotiate->machine_ctr);
			return 0;
		} else {
			if (negotiate->machine_ctr <= circ->padding_machine_ctr) {
				EWFD_LOG("OR stop old padding unit: %u %u", negotiate->machine_type, negotiate->machine_ctr);
				return 0;
			} else {
				EWFD_LOG("WARN: OR stop unkown padding unit: %u %u", negotiate->machine_type, negotiate->machine_ctr);
				return -1;
			}
		}
	} 
	else if (negotiate->command == CIRCPAD_COMMAND_EWFD_DATA) {

	}

	return 0;
}

int remove_ewfd_units_on_circ(circuit_t *circ) {

}


int trigger_ewfd_units_on_circ(circuit_t *circ) {

}


/** ----------------------------------------------------------
	Private Functions
*/
static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_conf_st *conf, uint32_t unit_version) {
	ewfd_padding_unit_st *unit = tor_malloc_zero(sizeof(ewfd_padding_unit_st));
	unit->conf = conf;
	unit->unit_version = unit_version;
	return unit;
}

static int free_ewfd_padding_unit(circuit_t *circ, int unit_uuid, uint32_t unit_version) {
	int found = 0;

	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
		if (circ->ewfd_padding_unit[i] && circ->ewfd_padding_unit[i]->conf->unit_uuid == unit_uuid) {
			if (circ->padding_machine_ctr == unit_version) {
				tor_free(circ->ewfd_padding_unit[i]);
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

// 根据收到的unit type，找到已有的padding unit，到or_circ
static bool ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid) {

	ewfd_padding_conf_st *target_conf = NULL;

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
		free_ewfd_padding_unit(circ, unit_uuid, circ->padding_machine_ctr);
		EWFD_LOG("Unit already exists. Replace");
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
		EWFD_LOG("Unit: %u is added to relay/or_circ", unit_uuid);
	}

	return true;
}
