#ifndef EWFD_H_
#define EWFD_H_

/*
Padding 框架，全局timer，padding ebpf conf 生命周期管理
基于全局队列的细粒度padding op实现
*/

#include "lib/smartlist_core/smartlist_core.h"

#include "lib/evloop/compat_libevent.h"
#include "core/or/or.h"
#include <stdint.h>

// struct ewfd_conf_cache

struct ewfd_event_queue_t;
struct ewfd_delay_queue_t;

// 固定tick调用，dummy queue和padding unit
typedef struct ewfd_framework_t {
	struct ewfd_event_queue_t *ewfd_event_queue;
	struct ewfd_delay_queue_t *ewfd_delay_queue;

	// smartlist_t *
	periodic_timer_t *padding_ticker; // 当前不使用
	periodic_timer_t *packet_ticker;  // 固定tick处理
	uint64_t last_event_ti; // 上一次发送event的时间
	uint32_t all_dummy_pkt; // 总共发送的dummy packet数量

	// hash map，记录每个cicr的event堆积数量
	// 见 ewfd_get_remain_events 

} ewfd_framework_st;

// read from local confs
extern smartlist_t *client_unit_confs;
extern ewfd_framework_st *ewfd_framework;

// init ewfd padding framework
void ewfd_framework_init(void);
void ewfd_framework_free(void);

void start_ewfd_padding_framework(void);
void ewfd_remove_circ_events(uintptr_t on_circ);


#ifdef EWFD_UNITEST_TEST_PRIVATE
// struct ewfd_event_queue_t;

// ewfd_event_queue_t *ewfd_event_queue_new(void);
// void ewfd_event_queue_free(ewfd_event_queue_t *event_queue);	

extern void on_event_queue_tick(periodic_timer_t *timer, void *data);

#endif // EWFD_UNITEST_TEST_PRIVATE

#endif
