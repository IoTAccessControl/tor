#ifndef EWFD_PADDING_H_
#define EWFD_PADDING_H_

#include "core/or/or.h"
#include "lib/evloop/timers.h"
#include "trunnel/circpad_negotiation.h"
#include <stdint.h>
#include <stdbool.h>
#include "feature/ewfd/ewfd_unit.h"


#define MAX_EWFD_UNITS_ON_CIRC 5
#define MAX_EWFD_REQUEST_RETRY 5
#define UNRECOGNISED_RELAY_COMMAND 0 // forward a relay packet 

enum {
	EWFD_UNIT_SCHEDULE,
	EWFD_UNIT_PADDING,
};

enum {
	EWFD_SCHEDULE_RESET_UNIT = 1,
};

enum {
	EWFD_OP_DUMMY_PACKET = 1,
	EWFD_OP_DELAY_PACKET,
};

enum {
	EWFD_PEER_NONE = 0, // 初始状态，没有setup unit到slot
	EWFD_PEER_CREATE,
	EWFD_PEER_WORK,
	EWFD_PEER_PAUSE,
	EWFD_PEER_CLEAR,
	EWFD_PEER_STATE_MAX,
};

/**
unit_uuid: 脚本编号
*/
typedef struct ewfd_padding_conf_t {
	uint8_t unit_uuid;
	uint8_t unit_type; // schedule or padding unit
	uint8_t initial_hop; // bit3, [Exit][OR][Client]
	uint8_t target_hopnum;
	uint32_t tick_interval;  // ms for tick gap, 10-6 second, 
	bool use_jit;
	ewfd_code_st *init_code; // init map/timeline
	ewfd_code_st *main_code; // logic
} ewfd_padding_conf_st;

struct ewfd_unit_t;

/** 将conf，脚本绑定到一个vm上
*/
typedef struct ewfd_padding_unit_t {
	uint8_t unit_version; 	// 区分同一uuid的padding unit, version = current unit_cnt
	uint8_t peer_state;		// 确认peer是否已经启动
	uint8_t retry_num;		// 重试次数
	struct ewfd_padding_conf_t *conf;
	struct ewfd_unit_t *ewfd_unit; // 保存ebpf jit函数
} ewfd_padding_unit_st;

/** 传递到eBPF vm的参数，一块连续的内存
*/
typedef struct ewfd_circ_status_t {
	uint64_t ewfd_unit;
	// __IN
	// uint32_t last_delay_ti;
	uint32_t padding_start_ti; // first padding init time
	uint32_t last_padding_ti;  // previous padding unit exec time
	uint32_t last_cell_ti;     // last cell send/receive time
	uint32_t now_ti;
	
	uintptr_t on_circ;

	uint32_t send_cell_cnt;
	uint32_t recv_cell_cnt;

	// command 
	uint8_t cur_padding_unit;
	uint8_t last_relay_cmd;
	uint8_t current_relay_cmd;

	// __OUT 
	uint32_t next_tick;
} __attribute__((packed, aligned(4))) ewfd_circ_status_st;

// // 当前直接用函数：ewfd_padding_op
// typedef struct ewfd_padding_op_t {
// 	void (*ewfd_dummy_packet)(circuit_t *circ, uint32_t delay);
// 	bool (*ewfd_delay_packet)(circuit_t *circ, uint32_t delay);
// } ewfd_padding_op_st;
// extern ewfd_padding_op_st *ewfd_padding_op;

/** ewfd unit触发，调用ebpf vm
*/
typedef struct ewfd_unit_ctx_t {
	uint8_t active_slot; // 同一时刻只能执行一种unit
	bool is_enable;		 // timer is scheduled
	uint32_t next_tick;  // fixed gap, 所有的时间单位都是ms
	uint32_t last_tick_ti; // abusolute time of last tick
	uint32_t padding_start_ti; // abusoluate time
	uint32_t total_dummy_pkt;
	uint32_t total_delay_pkt;
	tor_timer_t *ticker;
} ewfd_unit_ctx_st;

/** 目标：padding-unit和schedule-unit尽量共享最多的结构体，ctx只需要一个，避免同步tor状态同步两次
支持两种eWFD unit：
- 算法选择unit
- 算法实现unit
两种unit共享ctx结构体。
*/
typedef struct ewfd_padding_runtime_t {
	ewfd_padding_unit_st *schedule_slots[MAX_EWFD_UNITS_ON_CIRC]; // 部署多个schedule算法, 同时只能启用一个 
	ewfd_padding_unit_st *padding_slots[MAX_EWFD_UNITS_ON_CIRC];  // 部署多个padding算法, 同时只能启用一个
	uint8_t units_num;											  // 记录当前剩余unit数量, all - release。用于调试，确保内存分配正确
	uint8_t last_unit_idx; 										  // 一共多少个unit, 记录当前unit version（只增不减）
	circuit_t *on_circ;
	char circ_tag[64]; 											 // for debug
	struct ewfd_circ_status_t circ_status;
	struct ewfd_unit_ctx_t schedule_unit_ctx;
	struct ewfd_unit_ctx_t padding_unit_ctx;
} ewfd_padding_runtime_st;


int ewfd_handle_padding_negotiate(circuit_t *circ, circpad_negotiate_t *negotiate);
int ewfd_handle_padding_negotiated(circuit_t *circ, circpad_negotiated_t *negotiated);

// dispatch padding commands
int add_ewfd_units_on_circ(circuit_t *circ);
void free_all_ewfd_units_on_circ(circuit_t *circ);
void on_ewfd_rt_destory(circuit_t *circ);

uint8_t get_current_padding_unit_slot(ewfd_padding_runtime_st *ewfd_rt, uint8_t uuid);
uint8_t get_current_padding_unit_uuid(ewfd_padding_runtime_st *ewfd_rt);

int trigger_ewfd_units_on_circ(circuit_t *circ, bool is_send, bool toward_origin, uint8_t relay_command);

bool ewfd_schedule_op(circuit_t *circ, uint8_t op, uint8_t target_unit, void *args);

bool ewfd_padding_op(int op, circuit_t *circ, uint32_t delay);

const char *padding_state_to_str(uint8_t state);

// other events
// int on_add_ewfd_units_on_circ();
// int on_remove_ewfd_units_on_circ();

#endif