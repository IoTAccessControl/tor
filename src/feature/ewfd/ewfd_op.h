#ifndef EWFD_OP_H_
#define EWFD_OP_H_

#include <stdint.h>
#include "core/or/or.h"

/* 判断是否是delay包
等待delay_us后发送n个包
n_cell: 实际从队列删除的包的数量
*/
extern packed_cell_t* ewfd_cell_queue_pop_simple_delay(cell_queue_t *queue, uint8_t wide_circ_ids, uint8_t *n_cell);
extern packed_cell_t* ewfd_craft_dummy_packet(circuit_t *circ);

// extern packed_cell_t* ewfd_cell_queue_pop_advance_delay(cell_queue_t *queue, uint8_t wide_circ_ids, uint8_t *n_cell);


/*
*   内部其他PAI
*/
/* op最终实现，给ewfd.c中的队列调用
*/
// 发送一个delay event
bool ewfd_paddding_op_delay_impl(circuit_t *circ, uint32_t trigger_ms, uint32_t pkt_num);

// 唤醒被delay的circ
bool ewfd_paddding_op_delay_notify_impl(circuit_t *circ);

// 发送dummy包
bool ewfd_paddding_op_dummy_impl(circuit_t *circ);

bool ewfd_paddding_op_delay_gap_impl(circuit_t *circ, uint32_t trigger_ms, uint32_t pkt_num);

bool ewfd_padding_trigger_inactive_circ(circuit_t *circ, uint64_t tick_ms);

#endif // EWFD_OP_H_
