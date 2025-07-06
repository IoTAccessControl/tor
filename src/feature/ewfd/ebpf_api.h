#ifndef EWFD_EBPF_API_H_
#define EWFD_EBPF_API_H_

#include <stdint.h>

/*
*   eWFD-eBPF API
*/
// ebpf端接口
// add to global timer and sending queue
// are implemented in ewfd.c
int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti);
// 基于delay事件的实现  
int ewfd_add_delay_packet(uintptr_t on_circ, uint32_t insert_ti, uint32_t delay_to_ms, uint32_t pkt_num);

// 基于拥塞控制（自定义sleep队列）的实现  
int ewfd_op_delay(uintptr_t on_circ, uint32_t insert_ti, uint32_t delay_ms, uint32_t pkt_num);


// 获取当前circ上的delay事件，如果太多就不需要调度了
int ewfd_get_event_num(uintptr_t on_circ);



#endif // EWFD_EBPF_API_H_
