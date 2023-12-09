#include "feature/ewfd/ewfd_rt.h"
#include "feature/ewfd/ewfd_dev.h"
#include "feature/ewfd/circuit_padding.h"
#include "feature/ewfd/debug.h"
#include "feature/ewfd/ewfd_unit.h"
#include "lib/ebpf/ebpf_vm.h"
#include "lib/ebpf/ewfd-defense/src/ewfd_api.h"

#include <assert.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

// #include "lib/ebpf/ewfd-defense/src/ewfd_ctx.h"


// typedef struct front_padding_demo_t {
// 	int 
// } front_padding_demo_st;

/**
方案-1：每个tick一个padding
方案-2：通过helper调用，发送多个dummy packet（定时器）
性能消耗都一样，因此方案-1更好。
*/


/**
1. 生成200个数据，sorted 
2. 如果用完了再次生成
*/

// #define USE_C_DEBUG_CODE

/*
测试阶段，一次生成3-5个padding包
*/
void run_ewfd_schedule_vm(ewfd_padding_runtime_st *ewfd_rt) {
	uint32_t now_ti = monotime_absolute_msec();
	ewfd_rt->circ_status.now_ti = now_ti;
	ewfd_rt->circ_status.cur_padding_unit = get_current_padding_unit_uuid(ewfd_rt);

	// 根据flow状态，开启和切换算法
	uint64_t ret = 0;

#define USE_C_DEBUG_CODE
#ifdef USE_C_DEBUG_CODE
	ret = ewfd_default_schedule_unit(&ewfd_rt->circ_status);
#else
	// run current padding unit
	ewfd_unit_st * unit = ewfd_rt->schedule_slots[ewfd_rt->schedule_unit_ctx.active_slot];
	ret = run_ewfd_unit(unit, &ewfd_rt->circ_status, sizeof(ewfd_circ_status_st));
#endif // USE_C_DEBUG_CODE
	
	int op = (int) (ret >> 32);
	int args = (int) (ret & 0xffffffff);

	// reset next trigger ti
	if (ewfd_rt->circ_status.next_tick != 0) {
		ewfd_rt->schedule_unit_ctx.next_tick = ewfd_rt->circ_status.next_tick;
	} else {
		int slot = ewfd_rt->schedule_unit_ctx.active_slot;
		assert(ewfd_rt->schedule_slots[slot] && ewfd_rt->schedule_slots[slot]->conf);
		ewfd_rt->schedule_unit_ctx.next_tick = ewfd_rt->schedule_slots[slot]->conf->tick_interval;
	}

	if (op == EWFD_SCHEDULE_RESET_UNIT) {
		uint8_t unit_uuid = (uint8_t) args >> 8;
		uint8_t state = (uint8_t) args & 0xff;

		ewfd_schedule_op(ewfd_rt->on_circ, EWFD_SCHEDULE_RESET_UNIT, unit_uuid, &state);
		// EWFD_LOG("[schedule-unit] reset unit: %d, state: %d", unit_uuid, state);
	}
}

void run_ewfd_padding_vm(ewfd_padding_runtime_st *ewfd_rt) {
	// front 算法

	// schedule
	if (ewfd_rt->padding_unit_ctx.total_dummy_pkt > 1000) {
		EWFD_LOG("exceed maxiam dummy packet\n");
		return;
	}
	ewfd_rt->circ_status.now_ti = monotime_absolute_msec();

	uint64_t ret = 0;

#undef USE_C_DEBUG_CODE
#ifdef USE_C_DEBUG_CODE
	ret = ewfd_default_padding_unit(&ewfd_rt->circ_status);
#else
	// EWFD_LOG("---------------------: run ebpf tick");
	// run current padding unit
	ewfd_padding_unit_st * unit = ewfd_rt->padding_slots[ewfd_rt->padding_unit_ctx.active_slot];
	ewfd_rt->circ_status.ewfd_unit = (uint64_t) unit->ewfd_unit;
	ret = run_ewfd_unit(unit->ewfd_unit, &ewfd_rt->circ_status, sizeof(ewfd_circ_status_st));

#endif // USE_C_DEBUG_CODE

	uint32_t now_ti = monotime_absolute_msec();
	int op = (int) (ret >> 32);
	int args = (int) (ret & 0xffffffff);
	if (ewfd_rt->circ_status.next_tick != 0) {
		ewfd_rt->padding_unit_ctx.next_tick = ewfd_rt->circ_status.next_tick;
	} else {
		int slot = ewfd_rt->padding_unit_ctx.active_slot;
		ewfd_rt->padding_unit_ctx.next_tick = ewfd_rt->padding_slots[slot]->conf->tick_interval;
	}

	// 暂时只支持dummy packet
	if (op == EWFD_OP_DUMMY_PACKET) {
		ewfd_rt->circ_status.last_padding_ti = now_ti;
		// ewfd_padding_op(op, ewfd_rt->on_circ, args);
		ewfd_rt->padding_unit_ctx.total_dummy_pkt += args;
	}
}
