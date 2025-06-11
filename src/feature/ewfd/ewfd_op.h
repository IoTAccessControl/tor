#ifndef EWFD_OP_H_
#define EWFD_OP_H_

#include <stdint.h>
#include "core/or/or.h"

// ebpf端接口
// add to global timer and sending queue
// are implemented in ewfd.c
extern int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti);
// 基于delay事件的实现  
extern int ewfd_add_delay_packet(uintptr_t on_circ, uint32_t insert_ti, uint32_t delay_to_ms, uint32_t pkt_num);
// 基于拥塞控制（自定义sleep队列）的实现  
extern int ewfd_op_delay(uintptr_t on_circ, uint32_t insert_ti, uint32_t delay_to_ms, uint32_t pkt_num);

/* 判断是否是delay包
等待delay_us后发送n个包
n_cell: 实际从队列删除的包的数量
*/
extern packed_cell_t* ewfd_cell_queue_pop(cell_queue_t *queue, uint8_t wide_circ_ids, uint8_t *n_cell);

/* op最终实现，给ewfd.c中的队列调用
*/
// 发送一个delay event
bool ewfd_paddding_op_delay_impl(circuit_t *circ, uint32_t trigger_ms, uint32_t pkt_num);

// 唤醒被delay的circ
bool ewfd_paddding_op_delay_notify_impl(circuit_t *circ);

// 发送dummy包
bool ewfd_paddding_op_dummy_impl(circuit_t *circ);

bool ewfd_paddding_op_delay_gap_impl(circuit_t *circ, uint32_t trigger_ms, uint32_t pkt_num);

#endif // EWFD_OP_H_
