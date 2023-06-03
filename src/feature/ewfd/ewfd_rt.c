#include "feature/ewfd/ewfd_rt.h"
#include "feature/ewfd/ewfd_dev.h"
#include "feature/ewfd/circuit_padding.h"
#include "feature/ewfd/debug.h"
#include <stdint.h>

#include <math.h>
#include <stdlib.h>


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


/*
测试阶段，一次生成3-5个padding包
*/
void run_ewfd_schedule_vm(ewfd_padding_runtime_st *ewfd_rt) {
	uint32_t now_ti = monotime_absolute_msec();
	ewfd_rt->circ_status.now_ti = now_ti;

	// 根据flow状态，开启和切换算法
	uint64_t ret = ewfd_default_schedule_unit(&ewfd_rt->circ_status);
	
	int op = (int) (ret >> 32);
	int args = (int) (ret & 0xffffffff);

	if (op == EWFD_SCHEDULE_RESET_UNIT) {
		uint8_t unit_uuid = (uint8_t) args >> 8;
		uint8_t state = (uint8_t) args & 0xff;

		ewfd_schedule_op(ewfd_rt->on_circ, EWFD_SCHEDULE_RESET_UNIT, unit_uuid, &state);
		EWFD_LOG("[schedule-unit] reset unit: %d, state: %d", unit_uuid, state);
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

	uint64_t ret = ewfd_default_padding_unit(&ewfd_rt->circ_status);

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
		ewfd_rt->circ_status.last_padding_ti = monotime_absolute_msec();
		// ewfd_padding_op(op, ewfd_rt->on_circ, args);
		ewfd_rt->padding_unit_ctx.total_dummy_pkt += args;
	}
}