#include "feature/ewfd/circuit_padding.h"
#include "feature/ewfd/ewfd_unit.h"
#include "feature/ewfd/utils.h"
#include "feature/ewfd/debug.h"
#include "feature/ewfd/ewfd_rt.h"
#include "feature/ewfd/ewfd_conf.h"
#include "feature/ewfd/ewfd.h"
#include "feature/ewfd/ewfd_ticker.h"

#include "circpad_negotiation.h"
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/or.h"
#include "core/or/command.h"
#include "core/or/relay.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "lib/evloop/timers.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "core/or/circuitpadding.h"
#include "lib/defs/time.h"
#include "feature/stats/rephist.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


// 避免循环引用：由ewfd引用circuit_padding
// #include "feature/ewfd/ewfd.h"


// extern smartlist_t *client_unit_confs;
// extern 

/**
协议：
1. 通过CIRCPAD_COMMAND_EWFD_DATA来同步padding units配置，指定当前circ需要使用的padding unit，
	让relay去下载或者同步这些需要padding units。
2. circpad_negotiate_t，两边保持强同步
- machine_type：uuid
- machine_ctr: state | （version?） 传输额外state，每个命令不同  
  由于circuit可能会被复用？前后对应的是不同的stream，但是始终属于同一个用户，circuit上的padding units是否需要version字段？

schedule unit:
- 当前实现一个最简单的schedule unit, 超过500ms没有发包就disable padding unit

*/

#define DSIABLE_EWFD 0

// state, machine_ctr里面传输
const char *ewfd_peer_state_str[] = {
	"EWFD_PEER_NONE",
	"EWFD_PEER_CREATE",
	"EWFD_PEER_WORK",
	"EWFD_PEER_PAUSE",
	"EWFD_PEER_CLEAR",
};


static void ewfd_init_runtime(circuit_t *circ);
static int ewfd_release_runtime(circuit_t *circ);

// padding unit的内存由circ管理，在circ关闭时一起关
static int padding_units_num = 0;
static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_runtime_st *cur_rt, ewfd_padding_conf_st *conf);
static void free_ewfd_padding_unit(ewfd_padding_runtime_st *cur_rt, ewfd_padding_unit_st *unit);
static ewfd_padding_unit_st* ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid, bool replace);
static ewfd_padding_unit_st* ewfd_get_unit_on_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid);
static bool ewfd_active_unit_by_uuid(ewfd_padding_runtime_st *ewfd_rt, uint8_t unit_uuid);
static bool free_ewfd_padding_unit_by_uuid(circuit_t *circ, int unit_uuid, uint32_t unit_version);

static bool ewfd_peer_is_created(int peer_state);

/** ewfd unit设计：
- Type-1 padding算法选择和切换的unit
- Type-2 padding算法unit

circuit建立阶段：
COMMAND_DATA: 传输units到peer
COMMAND_START: 安装和传输padding/schedule unit，初始化资源
COMMAND_STOP: 停止padding/schedule unit, 回收内存

circuit传输阶段：
COMMAND_RESET：stop -> start / start -> stop

发送包事件：（选择padding算法，控制生命周期）
- 在发送包的时候按照tick触发一个算法选择和切换的unit。
- 根据命令选择和开启timer

timer：(确认是否需要增加padding，真正增加padding)
- 被开启之后按照tick触发回调，插入padding包
*/
static bool reset_ewfd_padding_unit_on_circ(circuit_t *circ, uint8_t state);
// static bool deactive_ewfd_padding_unit_on_circ(circuit_t *circ);

static bool run_efwd_schedule_unit(ewfd_padding_runtime_st *ewfd_rt);
static bool start_efwd_schedule_ticker(ewfd_padding_runtime_st *ewfd_rt);
static bool start_efwd_padding_ticker(ewfd_padding_runtime_st *ewfd_rt);
static void halt_ewfd_padding_ticker(ewfd_padding_runtime_st *ewfd_rt);
static bool notify_peer_units_states(ewfd_padding_runtime_st *ewfd_rt, int state);
static void trigger_efwd_schedule_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time);
static void trigger_efwd_padding_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time);
// static int ewfd_padding_on_tick(circuit_t *circ);
// static int ewfd_padding_client_to_or(circuit_t *circ, uint8_t relay_command);
// static int ewfd_padding_or_to_client(circuit_t *circ);
// static int ewfd_padding_op_dummy_packet(circuit_t *circ);
// static int ewfd_padding_op_delay_packet(circuit_t *circ);


const char *padding_state_to_str(uint8_t state) {
	if (state >= 0 && state < EWFD_PEER_STATE_MAX) {
		return ewfd_peer_state_str[state];
	}
	return "UNKNOWN";
}

/** STEP-1: Origin(client) add padding unit, and send negotiate commands to OR
* unit_version: 用于判断某个slot的unit是否一致，增加一个Unit之后，version + 1 = machine_ctr
* neogation -> machine_ctr (发送增加之后的machine_tr)
*/
int add_ewfd_units_on_circ(circuit_t *circ) {
	if (!CIRCUIT_IS_ORIGIN(circ) || ewfd_client_conf == NULL || ewfd_client_conf->client_unit_confs == NULL) {
		return 0;
	}
	origin_circuit_t *on_circ = TO_ORIGIN_CIRCUIT(circ);
	int current_role = ewfd_get_node_role_for_circ(circ);

	if ((current_role & EWFD_NODE_ROLE_CLIENT) == 0) {
		return 0;
	}

	// 测试阶段临时disable ewfd
	#if DSIABLE_EWFD
		return 0;
	#endif

	if (circ->ewfd_padding_rt == NULL) {
		ewfd_init_runtime(circ);
	}
	
	// 如果全部加载完，只有发生变化才需要重新load
	bool all_peer_cteated = true;
	for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
		if (circ->ewfd_padding_rt->padding_slots[i] != NULL) {
			all_peer_cteated &= ewfd_peer_is_created(circ->ewfd_padding_rt->padding_slots[i]->peer_state);
		}
	}
	if (!ewfd_client_conf->need_reload && all_peer_cteated) {
		return 0;
	}
	// TODO: reload逻辑，先删除旧的unit

	// 初始化所有的padding machine
	smartlist_t* unit_confs = ewfd_client_conf->client_unit_confs;
	SMARTLIST_FOREACH_BEGIN(unit_confs, ewfd_padding_conf_st *, conf) {
		if (!(conf->initial_hop & current_role)) {
			continue;
		}

		ewfd_padding_unit_st *unit = ewfd_add_unit_to_circ_by_uuid(circ, conf->unit_uuid, false);

		// notify peer to enabel the same unit
		if (unit != NULL && !ewfd_peer_is_created(unit->peer_state) && unit->retry_num < MAX_EWFD_REQUEST_RETRY) {
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

	// no padding units added
	if (circ->ewfd_padding_rt->last_unit_idx == 0) {
		EWFD_LOG("WARNING: No padding units added on circ: %u", on_circ->global_identifier);
		return -1;
	}

	// set active slots
	circ->ewfd_padding_rt->padding_unit_ctx.active_slot = ewfd_client_conf->active_schedule_slot;
	circ->ewfd_padding_rt->schedule_unit_ctx.active_slot = ewfd_client_conf->active_padding_slot;
	
	return 0;
}

void free_all_ewfd_units_on_circ(circuit_t *circ) {
	int free_num = 0;
	int all_num = 0;
	int remain_padding = 0;
	if (circ->ewfd_padding_rt != NULL) {
		all_num = circ->ewfd_padding_rt->last_unit_idx;
		free_num = ewfd_release_runtime(circ);
		remain_padding = all_num - free_num;
		EWFD_LOG("Free %d/%d eWFD units on circ: %u remain: %d", free_num, 
			all_num, ewfd_get_circuit_id(circ), remain_padding);
	}
}

// remove packet on queue
void on_ewfd_rt_destory(circuit_t *circ) {
	EWFD_LOG("----------------------------------on_ewfd_rt_destory: %u", ewfd_get_circuit_id(circ));
	remove_remain_dummy_packets((uintptr_t) circ);
	circ->ewfd_padding_rt->on_circ = NULL;
}

/** STEP-2: OR handle padding negotiate
* 只是传输和安装padding unit，不会启动padding 
*/
int ewfd_handle_padding_negotiate(circuit_t *circ, circpad_negotiate_t *negotiate) {
	int retval = 0;
	bool should_response = true;
	EWFD_LOG("STEP-2: handle negotiate: %d uuid:%u version:%u", negotiate->command, negotiate->machine_type, negotiate->machine_ctr);
	if (negotiate->command == CIRCPAD_COMMAND_EWFD_START) {
		ewfd_padding_unit_st *unit = ewfd_add_unit_to_circ_by_uuid(circ, negotiate->machine_type, true);
		if (unit != NULL) {
			// client can install padding unit on mutiple hops, machine_ctr is a local version of client
			if (circ->ewfd_padding_rt->last_unit_idx != negotiate->machine_ctr) {
				EWFD_LOG("WARN: Client and relay have different counts of padding units: "
					"%u vs %u", circ->ewfd_padding_rt->last_unit_idx, negotiate->machine_ctr);
				/* TODO: why this number is not equal ? 
					this path should only have one client to install padding unit.
				*/
				/* 现阶段只有一个unit, 其逻辑是，client 先init c->s的，然后server init s->c的，所以两边的version(padding unit)个数应该相等。
				如果不相等应该是消息不一致？这个circuit上的前面请求在5次retry没有让peer启动
				*/
				// assert(false);
			}
			// circpad_cell_event_nonpadding_received(circ);

			// TODO: 
			// reset_ewfd_padding_unit_on_circ(circ, unit);
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
			if (circ->ewfd_padding_rt != NULL && negotiate->machine_ctr <= circ->ewfd_padding_rt->last_unit_idx) {
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
	else if (negotiate->command == CIRCPAD_COMMAND_EWFD_STATE) {
		// set padding unit states on Relay
		// only peer is created can receive this command
		uint8_t unit_uuid = negotiate->machine_type;
		uint32_t state = negotiate->machine_ctr;
		if (state == EWFD_PEER_WORK) {
			if (ewfd_active_unit_by_uuid(circ->ewfd_padding_rt, unit_uuid)) {
				start_efwd_padding_ticker(circ->ewfd_padding_rt);
				EWFD_LOG("[padding-unit] %d change state to work", unit_uuid);
			} else {
				retval = -1;
			}
		} else if (state == EWFD_PEER_PAUSE) {
			halt_ewfd_padding_ticker(circ->ewfd_padding_rt);
			EWFD_LOG("[padding-unit] %d change state to pause", unit_uuid);
		}
	} 
	else {
		EWFD_LOG("WARN: OR received unknown padding command: %d", negotiate->command);
		retval = -1;
	}

	// 通常每个命令都要回复操作成功，除非是stop命令
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
	ewfd_padding_unit_st *unit = ewfd_get_unit_on_circ_by_uuid(circ, negotiated->machine_type);
	uint32_t global_id = -1;
	if (CIRCUIT_IS_ORIGIN(circ)) {
		global_id = TO_ORIGIN_CIRCUIT(circ)->global_identifier;
	}

	EWFD_LOG("STEP-3: handle negotiated: %d uuid:%u version:%u circ: %u", negotiated->command, 
		negotiated->machine_type, negotiated->machine_ctr, global_id);
	if (negotiated->command == CIRCPAD_COMMAND_EWFD_STOP) {
		EWFD_LOG("Received STOP command on PADDING_NEGOTIATED for circuit %u", global_id);
		free_ewfd_padding_unit_by_uuid(circ, negotiated->machine_type, negotiated->machine_ctr);
	} else if (negotiated->command == CIRCPAD_COMMAND_EWFD_START) {
		if (negotiated->response == CIRCPAD_RESPONSE_ERR) {
			// 如果Machine存在了就释放，并报错
			if (free_ewfd_padding_unit_by_uuid(circ, negotiated->machine_type, negotiated->machine_ctr)) {
				EWFD_LOG("WARN: Middle node did not accept our padding request on circuit "
					"%u (%d)", TO_ORIGIN_CIRCUIT(circ)->global_identifier, circ->purpose);
			}
		} else {
			if (unit != NULL) {
				unit->peer_state = EWFD_PEER_CREATE;
				unit->retry_num = 0; // 重置重试次数
				// reset_ewfd_padding_unit_on_circ(circ, unit);
				EWFD_LOG("Seuccess to init EWFD Padding Unit on peer uuid:%u version:%u circ: %u", 
					negotiated->machine_type, negotiated->machine_ctr, global_id);
			}
		}
	} else if (negotiated->command == CIRCPAD_COMMAND_EWFD_STATE) {
		if (negotiated->response == CIRCPAD_RESPONSE_ERR) {
			EWFD_LOG("ERROR: Failed to change peer's state: %d on circuit "
				"%u (%d)", negotiated->machine_ctr, TO_ORIGIN_CIRCUIT(circ)->global_identifier, circ->purpose);
		} else { // success
			if (unit != NULL) {
				unit->peer_state = negotiated->machine_ctr;
				unit->retry_num = 0; // 重置重试次数
				EWFD_LOG("Seuccess to change peer's state: %s on circuit %u (%d)", ewfd_peer_state_str[negotiated->machine_ctr], 
					TO_ORIGIN_CIRCUIT(circ)->global_identifier, circ->purpose);
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

bool ewfd_schedule_op(circuit_t *circ, uint8_t op, uint8_t target_unit, void *args) {
	// ewfd_padding_unit_st *unit = ewfd_get_unit_on_circ_by_uuid(circ, target_unit);

	if (op == EWFD_SCHEDULE_RESET_UNIT) {
		uint8_t state = *(uint8_t *)args;
		if (state == EWFD_PEER_WORK) {
			circ->ewfd_padding_rt->padding_unit_ctx.active_slot = 
				get_current_padding_unit_slot(circ->ewfd_padding_rt, target_unit);
		}
		reset_ewfd_padding_unit_on_circ(circ, state);
	}
	return false;
}

/** 本函数在收发包的时候都会触发
在这里控制schedule unit/padding unit的生命周期

当前实现：
- （todo）唤醒Schudule Unit
- client: 直接在edge（client）发出begin的时候开始padding，
	收到end的时候停止padding。并且通知对端开启算法。暂时两边用一样的算法（unit uuid）
- relay: 啥都不干

Schedule Unit后续功能（如果长时间运行就需要切换算法）：
- 设置当前active padding unit slot
- 调整本端算法
- 设置对端的算法??
*/
int trigger_ewfd_units_on_circ(circuit_t *circ, bool is_send, bool toward_origin, uint8_t relay_command) {
	// no padding units on circ
	if (circ->ewfd_padding_rt == NULL) {
		return 0;
	}
	
	#if DSIABLE_EWFD
		return 0;
	#endif

	bool is_origin = CIRCUIT_IS_ORIGIN(circ);

	tor_assert(relay_command != RELAY_COMMAND_DROP);

	// step-1: start/stop schdule/padding unit
	// check and start schedule unit
	if (!circ->ewfd_padding_rt->schedule_unit_ctx.is_enable) {
		run_efwd_schedule_unit(circ->ewfd_padding_rt);
	}
	// TODO: trigger schedule unit on states changes
	uint32_t gid = ewfd_get_circuit_id(circ);

	// Client send BEGIN -> start relay's padding unit
	if (is_origin && relay_command == RELAY_COMMAND_BEGIN) {
		reset_ewfd_padding_unit_on_circ(circ, EWFD_PEER_WORK);
		EWFD_LOG("trigger_ewfd_units_on_circ [%d] active self/relay padding unit", gid);
	}

	// Client receive END -> stop relay's padding unit
	if (is_origin && !is_send && relay_command == RELAY_COMMAND_END) {
		reset_ewfd_padding_unit_on_circ(circ, EWFD_PEER_PAUSE);
		EWFD_LOG("trigger_ewfd_units_on_circ [%d] deactive self/relay padding", gid);
	} 
	
	// Relay Node UNRECOGNISED commond
	// do nothing
	EWFD_LOG("trigger_ewfd_units_on_circ [%u] is_send: %d edge: %d %s", gid, is_send, is_origin, show_relay_command(relay_command));

	// step-2: update packet status
	// if (relay_command != RELAY_COMMAND_DROP) {
		
	// }
	circ->ewfd_padding_rt->circ_status.last_cell_ti = monotime_absolute_msec();
	circ->ewfd_padding_rt->circ_status.send_cell_cnt += is_send;
	circ->ewfd_padding_rt->circ_status.recv_cell_cnt += !is_send;

	return 0;
}

uint8_t get_current_padding_unit_slot(ewfd_padding_runtime_st *ewfd_rt, uint8_t uuid) {
	for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
		if (ewfd_rt->padding_slots[i]->conf->unit_uuid == uuid) {
			return i;
		}
	}
	// should never reach here
	tor_assert(NULL);
	return 0;
}

uint8_t get_current_padding_unit_uuid(ewfd_padding_runtime_st *ewfd_rt) {
	uint8_t active_slot = ewfd_rt->padding_unit_ctx.active_slot;
	return ewfd_rt->padding_slots[active_slot]->conf->unit_uuid;
}

/** ----------------------------------------------------------
	Private Functions
*/

static void ewfd_init_runtime(circuit_t *circ) {
	EWFD_LOG("ewfd_init_runtime circ: %u", ewfd_get_circuit_id(circ));

	if (circ->ewfd_padding_rt == NULL) {
		circ->ewfd_padding_rt = tor_malloc_zero(sizeof(ewfd_padding_runtime_st));
		circ->ewfd_padding_rt->on_circ = circ;
		// memcpy(circ->ewfd_padding_rt->circ_tag, ewfd_get_circuit_info(circ), 60);
	}

	start_ewfd_padding_framework();
}

static int ewfd_release_runtime(circuit_t *circ) {
	int free_num = 0;
	if (circ->ewfd_padding_rt != NULL) {
		on_ewfd_rt_destory(circ);

		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->schedule_slots[i] != NULL) {
				free_ewfd_padding_unit(circ->ewfd_padding_rt, circ->ewfd_padding_rt->schedule_slots[i]);
				circ->ewfd_padding_rt->schedule_slots[i] = NULL;
				free_num++;
			}
		}
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->padding_slots[i] != NULL) {
				free_ewfd_padding_unit(circ->ewfd_padding_rt, circ->ewfd_padding_rt->padding_slots[i]);
				circ->ewfd_padding_rt->padding_slots[i] = NULL;
				free_num++;
			}
		}

		assert(circ->ewfd_padding_rt->units_num == 0);

		// free timer
		ewfd_free_ticker(&circ->ewfd_padding_rt->padding_unit_ctx.ticker);
		ewfd_free_ticker(&circ->ewfd_padding_rt->schedule_unit_ctx.ticker);

		EWFD_LOG("ewfd_release_runtime circ: %u", ewfd_get_circuit_id(circ));

		tor_free(circ->ewfd_padding_rt);
	}
	return free_num;
}

static ewfd_padding_unit_st* new_ewfd_padding_unit(ewfd_padding_runtime_st *cur_rt, ewfd_padding_conf_st *conf) {
	ewfd_padding_unit_st *unit = tor_malloc_zero(sizeof(ewfd_padding_unit_st));
	unit->conf = conf;
	unit->ewfd_unit = init_ewfd_unit(conf);
	cur_rt->units_num++;

	// increase padding machine counter, do not decrease
	cur_rt->last_unit_idx++;
	if (cur_rt->last_unit_idx == 0) { // overflow
		cur_rt->last_unit_idx = 1;
	}
	unit->unit_version = cur_rt->last_unit_idx;
	
	padding_units_num++;
	return unit;
}

static void free_ewfd_padding_unit(ewfd_padding_runtime_st *cur_rt, ewfd_padding_unit_st *unit) {
	padding_units_num--;
	cur_rt->units_num--;
	free_ewfd_unit(unit->ewfd_unit);
	tor_free(unit);
}

// 根据收到的unit type，找到已有的padding unit，到or_circ
static ewfd_padding_unit_st* ewfd_add_unit_to_circ_by_uuid(circuit_t *circ, uint8_t unit_uuid, bool replace) {
	ewfd_padding_conf_st *target_conf = NULL;
	smartlist_t *client_unit_confs = ewfd_client_conf->client_unit_confs;

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

	// relay peer's ewfd_padding_rt init here
	if (circ->ewfd_padding_rt == NULL) {
		ewfd_init_runtime(circ);
	}

	ewfd_padding_unit_st *cur_unit = ewfd_get_unit_on_circ_by_uuid(circ, unit_uuid);
	if (cur_unit != NULL && !replace) {
		EWFD_LOG("INGORE: padding unit already exists: %u version: %u", unit_uuid, cur_unit->unit_version);
		return cur_unit;
	}

	// repalce the previous unit if exist, otherwise put in the first empty slot
	int found = -1, first_empty_slot = -1, slot = 0;
	cur_unit = new_ewfd_padding_unit(circ->ewfd_padding_rt, target_conf);
	if (target_conf->unit_type == EWFD_UNIT_PADDING) {
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->padding_slots[i] == NULL && first_empty_slot == -1) {
				first_empty_slot = i;
			}
			if (circ->ewfd_padding_rt->padding_slots[i] 
					&& circ->ewfd_padding_rt->padding_slots[i]->conf->unit_uuid == unit_uuid) {
				found = i;
				break;
			}
		}

		// if full, put at 0 slot
		slot = found != -1 ? found : (first_empty_slot != -1 ? first_empty_slot : 0);
		if (circ->ewfd_padding_rt->schedule_slots[slot]) {
			free_ewfd_padding_unit(circ->ewfd_padding_rt, circ->ewfd_padding_rt->padding_slots[found]);
		}
		circ->ewfd_padding_rt->padding_slots[slot] = cur_unit;
	} else {
		for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
			if (circ->ewfd_padding_rt->schedule_slots[i] == NULL && first_empty_slot == -1) {
				first_empty_slot = i;
			}
			if (circ->ewfd_padding_rt->schedule_slots[i] 
				&& circ->ewfd_padding_rt->schedule_slots[i]->conf->unit_uuid == unit_uuid) {
				found = i;
				break;
			}
		}

		// if full, put at 0 slot
		slot = found != -1 ? found : (first_empty_slot != -1 ? first_empty_slot : 0);
		if (circ->ewfd_padding_rt->schedule_slots[slot]) {
			free_ewfd_padding_unit(circ->ewfd_padding_rt, circ->ewfd_padding_rt->schedule_slots[found]);
		}
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

static bool ewfd_active_unit_by_uuid(ewfd_padding_runtime_st *ewfd_rt, uint8_t unit_uuid) {
	for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
		if (ewfd_rt->schedule_slots[i] && 
				ewfd_rt->schedule_slots[i]->conf->unit_uuid == unit_uuid) {
			ewfd_rt->schedule_unit_ctx.active_slot = i;
			return true;
		}
	}
	for (int i = 0; i < MAX_EWFD_UNITS_ON_CIRC; i++) {
		if (ewfd_rt->padding_slots[i] && 
				ewfd_rt->padding_slots[i]->conf->unit_uuid == unit_uuid) {
			ewfd_rt->padding_unit_ctx.active_slot = i;
			return true;
		}
	}
	return false;
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
			free_ewfd_padding_unit(circ->ewfd_padding_rt, circ->ewfd_padding_rt->padding_slots[i]);
			circ->ewfd_padding_rt->padding_slots[i] = NULL;
			return true;
		}
	}

	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
		if (circ->ewfd_padding_rt->schedule_slots[i]->unit_version != unit_version) {
			EWFD_LOG("ERROR: schedule unit version mismatch. uuid: %d, version: %d, expected: %d", unit_uuid, unit_version, circ->ewfd_padding_rt->schedule_slots[i]->unit_version);
		}
		free_ewfd_padding_unit(circ->ewfd_padding_rt, circ->ewfd_padding_rt->schedule_slots[i]);
		circ->ewfd_padding_rt->schedule_slots[i] = NULL;
		return true;
	}
	return false;
}

static bool notify_peer_units_states(ewfd_padding_runtime_st *ewfd_rt, int state) {
	int active_slot = ewfd_rt->padding_unit_ctx.active_slot;
	tor_assert(ewfd_rt->padding_slots[active_slot]);

	if (!CIRCUIT_IS_ORIGIN(ewfd_rt->on_circ)) { // only client can notify peers
		return false;
	}

	ewfd_padding_unit_st *unit = ewfd_rt->padding_slots[active_slot];
	ewfd_padding_conf_st *conf = ewfd_rt->padding_slots[active_slot]->conf;

	EWFD_LOG("Notify peer units state: %d on circ: %d", state, TO_ORIGIN_CIRCUIT(ewfd_rt->on_circ)->global_identifier);

	if (!ewfd_peer_is_created(unit->peer_state)) {
		EWFD_LOG("ERROR: peer is not created. unit: %u", conf->unit_uuid);
		return false;
	}

	if (circpad_negotiate_padding(TO_ORIGIN_CIRCUIT(ewfd_rt->on_circ), conf->unit_uuid,
			conf->target_hopnum,
			CIRCPAD_COMMAND_EWFD_STATE,
			state) < 0) {
		unit->retry_num += 1;
		EWFD_LOG("Faild to notify relay to init padding unit: %u %u state: %d", conf->unit_uuid, unit->unit_version, state);
		return false;
	}

	return true;
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

static bool ewfd_peer_is_created(int peer_state) {
	return peer_state >= EWFD_PEER_CREATE && peer_state < EWFD_PEER_CLEAR;
}

static int ewfd_padding_op_delay_packet(circuit_t *circ) {
	return 0;
}

/** 暂时 开启和停止都用 CIRCPAD_COMMAND_EWFD_STATE 命令。
1. 在begin的时候 active 
2. 通知peer enable
3. end的时候deactive
*/
static bool reset_ewfd_padding_unit_on_circ(circuit_t *circ, uint8_t state) {
	tor_assert(circ->ewfd_padding_rt); 

	int active_slot = circ->ewfd_padding_rt->padding_unit_ctx.active_slot;
	ewfd_padding_unit_st *active_unit = circ->ewfd_padding_rt->padding_slots[active_slot];

	if (active_unit == NULL) {
		EWFD_LOG("WARNING: padding unit is not found on slot: %d", active_slot);
		return false;
	}

	if (state == EWFD_PEER_WORK) { // enable padding unit
		if (!circ->ewfd_padding_rt->padding_unit_ctx.is_enable) {
			start_efwd_padding_ticker(circ->ewfd_padding_rt);
		}

		// notify peer, may need to retry??
		if (circ->ewfd_padding_rt->padding_slots[active_slot]->peer_state != EWFD_PEER_WORK) {
			return notify_peer_units_states(circ->ewfd_padding_rt, EWFD_PEER_WORK);
		}
	} else if (state == EWFD_PEER_PAUSE) { // pause padding unit
		halt_ewfd_padding_ticker(circ->ewfd_padding_rt);
		// do not need retry, peer will deactive automatically
		if (circ->ewfd_padding_rt->padding_slots[active_slot]->peer_state == EWFD_PEER_WORK) {
			return notify_peer_units_states(circ->ewfd_padding_rt, EWFD_PEER_PAUSE);
		}
	} else {
		EWFD_LOG("ERROR: invalid state: %d", state);
	}

	return false;
}

static bool run_efwd_schedule_unit(ewfd_padding_runtime_st *ewfd_rt) {
	tor_assert(ewfd_rt);
	ewfd_unit_ctx_st *schudule_ctx = &ewfd_rt->schedule_unit_ctx;
	int active_slot = schudule_ctx->active_slot;
	if (!ewfd_rt->schedule_slots[active_slot]) {
		EWFD_LOG("WARNING: schedule unit is not found on slot: %d", active_slot);
		return false;
	}
	// init，500ms 一次检查 
	if (!schudule_ctx->is_enable) {
		// start timer
		ewfd_rt->padding_unit_ctx.active_slot = 0;
		start_efwd_schedule_ticker(ewfd_rt);
	}

	// trigger unit, state change的时候手动触发吗？
	// 不要调用trigger_efwd_schedule_ticker，会增加两次timer
	// uint32_t now = monotime_absolute_msec();
	// if (schudule_ctx->next_tick > now) {
	// 	trigger_efwd_schedule_ticker(ewfd_rt->schedule_unit_ctx.ticker, ewfd_rt, NULL);
	// }

	return true;
}

static bool start_efwd_schedule_ticker(ewfd_padding_runtime_st *ewfd_rt) {
	int slot = ewfd_rt->schedule_unit_ctx.active_slot;
	tor_assert(ewfd_rt->schedule_slots[slot]);

	EWFD_LOG("start_efwd_schedule_ticker circ: %u", ewfd_get_circuit_id(ewfd_rt->on_circ));
	ewfd_init_ticker(&ewfd_rt->schedule_unit_ctx.ticker, trigger_efwd_schedule_ticker, ewfd_rt);

	// uint32_t next_tick = ewfd_rt->schedule_slots[slot]->conf->tick_interval;
	uint32_t next_tick = 1; // 第一次立刻触发
	ewfd_schedule_ticker(ewfd_rt->schedule_unit_ctx.ticker, next_tick);
	
	ewfd_rt->schedule_unit_ctx.is_enable = true;
	ewfd_rt->schedule_unit_ctx.padding_start_ti = (uint32_t) monotime_absolute_msec();
	ewfd_rt->circ_status.on_circ = (uintptr_t) ewfd_rt->on_circ;
	ewfd_rt->schedule_unit_ctx.next_tick = 0;
	ewfd_rt->schedule_unit_ctx.last_tick_ti = ewfd_rt->schedule_unit_ctx.padding_start_ti + next_tick;
	
	// mi->is_padding_timer_scheduled = 1;
#if 0
	EWFD_LOG("[schedule-tick-1] %s timer is added: %u next: %u", ewfd_rt->circ_tag, 
		next_tick, ewfd_rt->padding_unit_ctx.padding_start_ti);
#endif
	return true;
}

static bool start_efwd_padding_ticker(ewfd_padding_runtime_st *ewfd_rt) {
	int slot = ewfd_rt->padding_unit_ctx.active_slot;
	tor_assert(ewfd_rt->padding_slots[slot]);

	// set timer
	EWFD_LOG("start_efwd_padding_ticker circ: %u", ewfd_get_circuit_id(ewfd_rt->on_circ));
	ewfd_init_ticker(&ewfd_rt->padding_unit_ctx.ticker, trigger_efwd_padding_ticker, ewfd_rt);

	// uint32_t next_tick = ewfd_rt->padding_slots[slot]->conf->tick_interval;
	uint32_t next_tick = 1; // 第一次立刻触发

	ewfd_schedule_ticker(ewfd_rt->padding_unit_ctx.ticker, next_tick);
	
	uint32_t now_ti = (uint32_t) monotime_absolute_msec() + next_tick;
	ewfd_rt->padding_unit_ctx.is_enable = true;
	ewfd_rt->padding_unit_ctx.padding_start_ti = now_ti;
	ewfd_rt->circ_status.padding_start_ti = now_ti;
	ewfd_rt->circ_status.last_padding_ti = now_ti;
	ewfd_rt->circ_status.on_circ = (uintptr_t) ewfd_rt->on_circ;
	ewfd_rt->padding_unit_ctx.next_tick = 0;
	// ewfd_rt->padding_unit_ctx.next_tick = ewfd_rt->padding_unit_ctx.padding_start_ti;
	ewfd_rt->padding_unit_ctx.last_tick_ti = ewfd_rt->padding_unit_ctx.padding_start_ti;
	
	// mi->is_padding_timer_scheduled = 1;
	uint32_t gid = ewfd_get_circuit_id(ewfd_rt->on_circ);

#if 0
	EWFD_LOG("[padding-tick-1] [%u] timer is added: %u next: %u", gid, 
		next_tick, ewfd_rt->padding_unit_ctx.padding_start_ti);
#endif
	return true;
}

static void halt_ewfd_padding_ticker(ewfd_padding_runtime_st *ewfd_rt) {
	if (!ewfd_rt->padding_unit_ctx.is_enable) { // is not enabled
		return;
	}
	ewfd_rt->padding_unit_ctx.is_enable = false;
	if (ewfd_rt->padding_unit_ctx.ticker) {
		ewfd_remove_ticker(&ewfd_rt->padding_unit_ctx.ticker);
	}
#if 0
	EWFD_LOG("[padding-tick-s] [%u] slot: %d", ewfd_get_circuit_id(ewfd_rt->on_circ), ewfd_rt->padding_unit_ctx.active_slot);
#endif
}

static void trigger_efwd_schedule_ticker(tor_timer_t *timer, void *args, const struct monotime_t *time) {
	ewfd_padding_runtime_st *ewfd_rt = (ewfd_padding_runtime_st *)args;

	// handle schedule tick
	run_ewfd_schedule_vm(ewfd_rt);

	uint32_t now_ti = (uint32_t) monotime_absolute_msec();
	uint32_t detla = (uint32_t)(now_ti - ewfd_rt->schedule_unit_ctx.last_tick_ti);

	uint32_t next_tick = ewfd_rt->schedule_unit_ctx.next_tick;
	// schedule again
	if (next_tick != 0) {
		// struct timeval timeout;
		// timeout.tv_sec = next_tick * 1000 / TOR_USEC_PER_SEC;
		// timeout.tv_usec = (next_tick * 1000) % TOR_USEC_PER_SEC;
		// timer_schedule(ewfd_rt->schedule_unit_ctx.ticker, &timeout);
		ewfd_schedule_ticker(ewfd_rt->schedule_unit_ctx.ticker, next_tick);
	}

// 每个circuit每秒2次
#if 0
	uint32_t gid = ewfd_get_circuit_id(ewfd_rt->on_circ);
	EWFD_LOG("[schedule-tick-n] [%u] want: %u actual: %u delta: %u next: %u", gid, 
		ewfd_rt->schedule_unit_ctx.last_tick_ti, now_ti, detla, 
		ewfd_rt->schedule_unit_ctx.last_tick_ti + next_tick);
#endif
	ewfd_rt->schedule_unit_ctx.last_tick_ti = now_ti;
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
		ewfd_schedule_ticker(ewfd_rt->padding_unit_ctx.ticker, next_tick);
	}

#if 0
	uint32_t gid = ewfd_get_circuit_id(ewfd_rt->on_circ);
	EWFD_LOG("[padding-tick-n] [%u] want: %u actual: %u delta: %u next: %u", gid,
		ewfd_rt->padding_unit_ctx.last_tick_ti, now_ti, detla, 
		ewfd_rt->padding_unit_ctx.last_tick_ti + next_tick);
#endif
	ewfd_rt->padding_unit_ctx.last_tick_ti = now_ti;
}
