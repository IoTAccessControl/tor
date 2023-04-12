#include "feature/ewfd/circuit_padding.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "circpad_negotiation.h"
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/or.h"
#include "core/or/relay.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/ewfd/debug.h"
#include "lib/evloop/timers.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "core/or/circuitpadding.h"
#include "feature/ewfd/utils.h"
#include "lib/defs/time.h"
#include "feature/ewfd/ewfd_rt.h"
#include "feature/stats/rephist.h"

// 避免循环引用：由ewfd引用circuit_padding
// #include "feature/ewfd/ewfd.h"


extern smartlist_t *client_unit_confs;

/**
协议：
1. 通过CIRCPAD_COMMAND_EWFD_DATA来同步padding units配置，指定当前circ需要使用的padding unit，
	让relay去下载或者同步这些需要padding units。
2. 
*/

// padding unit的内存由circ管理，在circ关闭时一起关
static int padding_units_num = 0;
static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_conf_st *conf, uint32_t unit_version);
static void free_ewfd_padding_unit(ewfd_padding_unit_st *unit);
static ewfd_padding_unit_st* ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid, bool replace);
static ewfd_padding_unit_st* ewfd_get_unit_on_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid);
static bool free_ewfd_padding_unit_by_uuid(circuit_t *circ, int unit_uuid, uint32_t unit_version);

/** ewfd unit设计：
- Type-1 padding算法选择和切换的unit
- Type-2 padding算法unit


发送包事件：（选择padding算法，控制生命周期）
- 在发送包的时候按照tick触发一个算法选择和切换的unit。
- 根据命令选择和开启timer

timer：(确认是否需要增加padding，真正增加padding)
- 被开启之后按照tick触发回调，插入padding包
*/
static bool active_ewfd_unit_on_circ(circuit_t *circ, ewfd_padding_unit_st *unit);
static bool start_efwd_schedule_ticker(ewfd_padding_runtime_st *ewfd_rt);
static bool start_efwd_padding_ticker(ewfd_padding_runtime_st *ewfd_rt);
static void trigger_efwd_schedule_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time);
static void trigger_efwd_padding_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time);
// static int ewfd_padding_on_tick(circuit_t *circ);
// static int ewfd_padding_client_to_or(circuit_t *circ, uint8_t relay_command);
// static int ewfd_padding_or_to_client(circuit_t *circ);
// static int ewfd_padding_op_dummy_packet(circuit_t *circ);
// static int ewfd_padding_op_delay_packet(circuit_t *circ);


/** STEP-1: Origin(client) add padding unit, and send negotiate commands to OR
* unit_version: 用于判断某个slot的unit是否一致，增加一个Unit之后，version + 1 = machine_ctr
* neogation -> machine_ctr (发送增加之后的machine_tr)
*/
int add_ewfd_units_on_circ(circuit_t *circ) {
	if (!CIRCUIT_IS_ORIGIN(circ) || client_unit_confs == NULL) {
		return 0;
	}
	origin_circuit_t *on_circ = TO_ORIGIN_CIRCUIT(circ);
	int current_role = ewfd_get_node_role_for_circ(circ);

	// 初始化所有的padding machine
	SMARTLIST_FOREACH_BEGIN(client_unit_confs, ewfd_padding_conf_st *, conf) {
		if (!(conf->deploy_hop & current_role)) {
			continue;
		}

		ewfd_padding_unit_st *unit = ewfd_add_unit_to_circ_by_uuid(circ, conf->unit_uuid, false);

		// notify peer to enabel the same unit
		if (unit != NULL && !unit->peer_is_up && unit->retry_num < MAX_EWFD_REQUEST_RETRY) {
			EWFD_LOG("STEP-1: Notify hop: %d to init unit uuid:%u version:%u on circ: %u", conf->target_hopnum, conf->unit_uuid,
				circ->padding_machine_ctr, on_circ->global_identifier);
			// 通知relay开启对应的padding unit
			if (circpad_negotiate_padding(TO_ORIGIN_CIRCUIT(circ), conf->unit_uuid,
			conf->target_hopnum,
			CIRCPAD_COMMAND_EWFD_START,
			unit->unit_version) < 0) {
				unit->retry_num += 1;
				EWFD_LOG("Faild to notify relay to init padding unit: %u %u", conf->unit_uuid, unit->unit_version);
			}
		}
	} SMARTLIST_FOREACH_END(conf);
	
	return 0;
}

void free_all_ewfd_units_on_circ(circuit_t *circ) {
	int cid = CIRCUIT_IS_ORIGIN(circ) ? TO_ORIGIN_CIRCUIT(circ)->global_identifier : -1;
	int free_num = 0;
	int all_num = 0;
	int remain_padding = 0;
	if (circ->ewfd_padding_rt != NULL) {
		all_num = circ->ewfd_padding_rt->units_cnt;

		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->schedule_slots[i] != NULL) {
				free_ewfd_padding_unit(circ->ewfd_padding_rt->schedule_slots[i]);
				circ->ewfd_padding_rt->schedule_slots[i] = NULL;
				free_num++;
			}
		}
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->padding_slots[i] != NULL) {
				free_ewfd_padding_unit(circ->ewfd_padding_rt->padding_slots[i]);
				circ->ewfd_padding_rt->padding_slots[i] = NULL;
				free_num++;
			}
		}

		// free timer
		timer_free(circ->ewfd_padding_rt->padding_unit_ctx.ticker);
		timer_free(circ->ewfd_padding_rt->schedule_unit_ctx.ticker);

		remain_padding = circ->ewfd_padding_rt->units_cnt - free_num;
		tor_free(circ->ewfd_padding_rt);
	}
	if (free_num > 0) {
		EWFD_LOG("Step-n: Free %d/%d eWFD units on circ: %d remain: %d", free_num, 
			all_num, cid, remain_padding);
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
		ewfd_padding_unit_st *unit = ewfd_add_unit_to_circ_by_uuid(circ, negotiate->machine_type, true);
		if (unit != NULL) {
			if (circ->ewfd_padding_rt->units_cnt != negotiate->machine_ctr) {
				EWFD_LOG("WARN: Client and relay have different counts of padding units: "
					"%u vs %u", circ->ewfd_padding_rt->units_cnt, negotiate->machine_ctr);
			}
			// circpad_cell_event_nonpadding_received(circ);

			// TODO: 这里只启动schedule，padding unit由schedule启动
			active_ewfd_unit_on_circ(circ, unit);
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
			if (circ->ewfd_padding_rt != NULL && negotiate->machine_ctr <= circ->ewfd_padding_rt->units_cnt) {
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
				EWFD_LOG("ERROR: Middle node did not accept our padding request on circuit "
					"%u (%d)", TO_ORIGIN_CIRCUIT(circ)->global_identifier, circ->purpose);
			}
		} else {
			ewfd_padding_unit_st *unit = ewfd_get_unit_on_circ_by_uuid(circ, negotiated->machine_type);
			if (unit != NULL) {
				unit->peer_is_up = true;
				active_ewfd_unit_on_circ(circ, unit);
				EWFD_LOG("Seuccess to init EWFD Padding Unit on peer uuid:%u version:%u", negotiated->machine_type, negotiated->machine_ctr);
			}
		}
	}

	circpad_negotiated_free(negotiated);
	return 0;
}

/** 实现padding操作
*/
bool ewfd_padding_op(int op, circuit_t *circ, uint32_t delay) {
	tor_assert(circ->ewfd_padding_rt);
	int slot = circ->ewfd_padding_rt->padding_unit_ctx.active_slot;
	int hopnum = circ->ewfd_padding_rt->padding_slots[slot]->conf->target_hopnum;
	if (op == EWFD_OP_DELAY_PACKET) {
		EWFD_LOG("WARN: OP Delay is not impl");
		return false;
	} else if (op == EWFD_OP_DUMMY_PACKET) {
		crypt_path_t *target_hop = NULL;
		if (CIRCUIT_IS_ORIGIN(circ)) {
			target_hop = circuit_get_cpath_hop(TO_ORIGIN_CIRCUIT(circ), hopnum);
			if (target_hop == NULL) {
				EWFD_LOG("ERROD: Can't find target hop for padding: %d", hopnum);
				return false;
			}
		}
		rep_hist_padding_count_write(PADDING_TYPE_DROP);
		return relay_send_command_from_edge(0, circ, RELAY_COMMAND_DROP, NULL, 0, target_hop);
	}
	return false;
}

/** 本函数开启两个timer，更新本方向发包状态
1. 判断方向
Client(ORIGIN) -> OR
OR -> Client: 只处理CELL_DIRECTION_IN的包（moving towards the origin）
OR -> OR: CELL_DIRECTION_OUT忽略

2. 简单方案，这里只是启动ewfd unit的timer。并多个包检查一次是否切换padding 方案
- 第一个包启动，padding timer
- (也使用timer触发) 若干个包（或者基于timer）检查一次是否需要切换padding方案
两种padding unit的调用位置不同。

3. 启动和关闭timer，这里负责开启和关闭schedule unit。schedule负责开启和关闭padding unit。
当前实现：不管schedule，最简实现padding unit，再重构。握手完成之后由active_ewfd_unit_on_circ开启padding。
*/
int trigger_ewfd_units_on_circ(circuit_t *circ, bool is_send, bool toward_origin, uint8_t relay_command) {
	if (client_unit_confs == NULL) return 0;
	bool is_origin = CIRCUIT_IS_ORIGIN(circ);

	tor_assert(relay_command != RELAY_COMMAND_DROP);

	// no padding units on circ
	if (circ->ewfd_padding_rt == NULL) {
		return 0;
	}

	// step-1: update packet status

	// step-2: check if the timers are enabled
	if (!circ->ewfd_padding_rt->schedule_unit_ctx.is_enable) {
		//active_ewfd_unit_on_circ(circ, ewfd_padding_unit_st *unit)
	}

	// Client -> OR 
	if (is_origin && is_send) {
		EWFD_LOG("trigger_ewfd_units_on_circ Client -> OR ");
		// ewfd_padding_client_to_or(circ, relay_command);
	}

	// OR -> Client
	if (!is_origin && toward_origin) {
		EWFD_LOG("trigger_ewfd_units_on_circ OR -> Client ");
		// ewfd_padding_or_to_client(circ);
	}

	// tor-0.4.7.10/src/core/or/circuitpadding.c
	// TODO: 1. 重构
	// timer_cb_fn_t()
	// timer_schedule(mi->padding_timer, &timeout);


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
static ewfd_padding_unit_st* ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid, bool replace) {
	ewfd_padding_conf_st *target_conf = NULL;
	tor_assert(client_unit_confs);

	SMARTLIST_FOREACH_BEGIN(client_unit_confs, ewfd_padding_conf_st *, conf) {
		if (conf->unit_uuid == unit_uuid) {
			target_conf = conf;
			break;
		}
	} SMARTLIST_FOREACH_END(conf);

	if (target_conf == NULL) {
		EWFD_LOG("ERROR: conf for padding unit not found: %u", unit_uuid);
		return false;
	}

	if (circ->ewfd_padding_rt == NULL) {
		circ->ewfd_padding_rt = tor_malloc_zero(sizeof(ewfd_padding_runtime_st));
	}

	ewfd_padding_unit_st *cur_unit = ewfd_get_unit_on_circ_by_uuid(circ, unit_uuid);
	if (cur_unit != NULL) {
		if (replace) {
			free_ewfd_padding_unit(cur_unit);
		} else {
			EWFD_LOG("INGORE: padding unit already exists: %u version: %u", unit_uuid, cur_unit->unit_version);
			return cur_unit;
		}
	}
	//EWFD_LOG("not find unit, add new unit: %u %d", unit_uuid, cur_unit == NULL);
	// increase padding machine counter
	circ->ewfd_padding_rt->units_cnt++;
	if (circ->ewfd_padding_rt->units_cnt == 0) {
		circ->ewfd_padding_rt->units_cnt = 1;
	}
	
	// put in previous slot or empty slot 
	int found = -1, first_slot = -1, slot = 0;
	cur_unit = new_ewfd_padding_unit(target_conf, circ->ewfd_padding_rt->units_cnt);
	if (target_conf->unit_type == EWFD_UNIT_PADDING) {
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			first_slot = i;
			if (circ->ewfd_padding_rt->padding_slots[i] && circ->ewfd_padding_rt->padding_slots[i]->conf->unit_uuid == unit_uuid) {
				found = i;
				break;
			}
		}
		slot = found == -1 ? first_slot : found;
		circ->ewfd_padding_rt->padding_slots[slot] = cur_unit;
	} else {
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			first_slot = i;
			if (circ->ewfd_padding_rt->schedule_slots[i] && circ->ewfd_padding_rt->schedule_slots[i]->conf->unit_uuid == unit_uuid) {
				found = i;
				break;
			}
		}
		slot = found == -1 ? first_slot : found;
		circ->ewfd_padding_rt->schedule_slots[slot] = cur_unit;
	}

	if (CIRCUIT_IS_ORIGIN(circ)) {
		EWFD_LOG("Unit: %u is added to client/origin_circ: %d slot: %d", unit_uuid, TO_ORIGIN_CIRCUIT(circ)->global_identifier, slot);
	} else {
		EWFD_LOG("Unit: %u is added to relay/or_circ peer: %s slot: %d", unit_uuid, ewfd_get_circuit_info(circ), slot);
	}

	return cur_unit;
}

static ewfd_padding_unit_st* ewfd_get_unit_on_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid) {
	if (circ->ewfd_padding_rt == NULL) return NULL;
	for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
		if (circ->ewfd_padding_rt->schedule_slots[i] && circ->ewfd_padding_rt->schedule_slots[i]->conf->unit_uuid == unit_uuid) {
			return circ->ewfd_padding_rt->schedule_slots[i];
		}
	}
	for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
		if (circ->ewfd_padding_rt->padding_slots[i] && circ->ewfd_padding_rt->padding_slots[i]->conf->unit_uuid == unit_uuid) {
			return circ->ewfd_padding_rt->padding_slots[i];
		}
	}
	return NULL;
}

/**
@return find and free the padding unit, return true. otherwise, return false.
*/
static bool free_ewfd_padding_unit_by_uuid(circuit_t *circ, int unit_uuid, uint32_t unit_version) {
	if (circ->ewfd_padding_rt == NULL) return false;

	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
		if (circ->ewfd_padding_rt->padding_slots[i] && circ->ewfd_padding_rt->padding_slots[i]->conf->unit_uuid == unit_uuid) {
			if (circ->ewfd_padding_rt->padding_slots[i]->unit_version != unit_version) {
				EWFD_LOG("ERROR: padding unit version mismatch. uuid: %d, version: %d, expected: %d", unit_uuid, unit_version, circ->ewfd_padding_rt->padding_slots[i]->unit_version);
			}
			free_ewfd_padding_unit(circ->ewfd_padding_rt->padding_slots[i]);
			circ->ewfd_padding_rt->padding_slots[i] = NULL;
			return true;
		}
	}

	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
		if (circ->ewfd_padding_rt->schedule_slots[i]->unit_version != unit_version) {
				EWFD_LOG("ERROR: schedule unit version mismatch. uuid: %d, version: %d, expected: %d", unit_uuid, unit_version, circ->ewfd_padding_rt->schedule_slots[i]->unit_version);
		}
		free_ewfd_padding_unit(circ->ewfd_padding_rt->schedule_slots[i]);
		circ->ewfd_padding_rt->schedule_slots[i] = NULL;
		return true;
	}
	return false;
}

// static int ewfd_padding_on_tick(circuit_t *circ) {

// 	return 0;
// }

// static int ewfd_padding_client_to_or(circuit_t *circ, uint8_t relay_command) {
// 	return 0;
// }

// static int ewfd_padding_or_to_client(circuit_t *circ) {

// 	return 0;
// }

// static int ewfd_padding_op_dummy_packet(circuit_t *circ) {

// 	return 0;
// }


static int ewfd_padding_op_delay_packet(circuit_t *circ) {
	return 0;
}

/**
在任何stream变化的时候，触发add_ewfd_units_on_circ，由Client端启动padding，然后通知peer启动。
同时启动schedule unit和padding unit。
*/
static bool active_ewfd_unit_on_circ(circuit_t *circ, ewfd_padding_unit_st *unit) {
	tor_assert(circ->ewfd_padding_rt); 
	int slot = 0;
	circ->ewfd_padding_rt->on_circ = circ;
	memcpy(circ->ewfd_padding_rt->circ_tag, ewfd_get_circuit_info(circ), 60);
	if (unit->conf->unit_type == EWFD_UNIT_SCHEDULE) {
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->schedule_slots[i] && 
				circ->ewfd_padding_rt->schedule_slots[i]->conf->unit_uuid == unit->conf->unit_uuid) {
				slot = i;
				break;
			}
		}
		if (circ->ewfd_padding_rt->schedule_slots[slot] != NULL) {
			circ->ewfd_padding_rt->schedule_unit_ctx.active_slot = slot;
			return start_efwd_schedule_ticker(circ->ewfd_padding_rt);
		}
	} else {
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->padding_slots[i] && 
				circ->ewfd_padding_rt->padding_slots[i]->conf->unit_uuid == unit->conf->unit_uuid) {
				slot = i;
				break;
			}
		}
		if (circ->ewfd_padding_rt->padding_slots[slot] != NULL) {
			circ->ewfd_padding_rt->padding_unit_ctx.active_slot = slot;
			return start_efwd_padding_ticker(circ->ewfd_padding_rt);
		}
	}
	return false;
}

static bool start_efwd_schedule_ticker(ewfd_padding_runtime_st *ewfd_rt) {
	return true;
}

static bool start_efwd_padding_ticker(ewfd_padding_runtime_st *ewfd_rt) {
	tor_assert(ewfd_rt);

	// set timer
	if (!ewfd_rt->padding_unit_ctx.ticker) {
		ewfd_rt->padding_unit_ctx.ticker = timer_new(trigger_efwd_padding_ticker, ewfd_rt);
	} else { // set timer again if disabled
		timer_disable(ewfd_rt->padding_unit_ctx.ticker);
		timer_set_cb(ewfd_rt->padding_unit_ctx.ticker, trigger_efwd_padding_ticker, ewfd_rt);
	}
	
	// schedule timer
	int slot = ewfd_rt->padding_unit_ctx.active_slot;
	uint32_t next_tick = ewfd_rt->padding_slots[slot]->conf->tick_interval;

	// enable ticker
	struct timeval timeout;
	timeout.tv_sec = next_tick * 1000 / TOR_USEC_PER_SEC;
	timeout.tv_usec = (next_tick * 1000) % TOR_USEC_PER_SEC;
	timer_schedule(ewfd_rt->padding_unit_ctx.ticker, &timeout);
	
	ewfd_rt->padding_unit_ctx.is_enable = true;
	ewfd_rt->padding_unit_ctx.start_ti = (uint32_t) monotime_absolute_msec();
	ewfd_rt->circ_status.padding_bengin_ti = ewfd_rt->padding_unit_ctx.start_ti;
	ewfd_rt->circ_status.last_dummy_ti = ewfd_rt->padding_unit_ctx.start_ti;
	ewfd_rt->circ_status.on_circ = (uintptr_t) ewfd_rt->on_circ;
	ewfd_rt->padding_unit_ctx.last_tick_ti = ewfd_rt->padding_unit_ctx.start_ti + next_tick;
	
	// mi->is_padding_timer_scheduled = 1;
	EWFD_LOG("[padding-tick-1] %s timer is added: %u next: %u", ewfd_rt->circ_tag, next_tick, ewfd_rt->padding_unit_ctx.start_ti);
	return true;
}

static void trigger_efwd_schedule_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time) {

}

static void trigger_efwd_padding_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time) {
	ewfd_padding_runtime_st *ewfd_rt = (ewfd_padding_runtime_st *)args;

	// handle padding tick
	run_ewfd_padding_vm(ewfd_rt);

	uint32_t now_ti = (uint32_t) monotime_absolute_msec();
	uint32_t detla = (uint32_t)(now_ti - ewfd_rt->padding_unit_ctx.last_tick_ti);
	
	uint32_t next_tick = ewfd_rt->padding_unit_ctx.next_tick;
	// schedule again
	if (next_tick != 0) {
		struct timeval timeout;
		timeout.tv_sec = next_tick * 1000 / TOR_USEC_PER_SEC;
		timeout.tv_usec = (next_tick * 1000) % TOR_USEC_PER_SEC;
		timer_schedule(ewfd_rt->padding_unit_ctx.ticker, &timeout);
	}

	EWFD_LOG("[padding-tick-n] %s want: %u actual: %u delta: %u next: %u", ewfd_rt->circ_tag, 
		ewfd_rt->padding_unit_ctx.last_tick_ti, now_ti, detla, ewfd_rt->padding_unit_ctx.last_tick_ti + next_tick);
	ewfd_rt->padding_unit_ctx.last_tick_ti = now_ti;
}
