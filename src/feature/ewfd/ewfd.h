#ifndef EWFD_H_
#define EWFD_H_

#include "lib/smartlist_core/smartlist_core.h"

#include "lib/evloop/compat_libevent.h"

// struct ewfd_conf_cache

struct ewfd_packet_queue_t;

// 固定tick调用，dummy queue和padding unit
typedef struct ewfd_framework_t {
	struct ewfd_packet_queue_t *dummy_packet_queue;

	// smartlist_t *
	periodic_timer_t *padding_ticker; // 当前不使用
	periodic_timer_t *packet_ticker;  // 固定tick处理
	uint32_t last_packet_ti; // 上一次发送dummy packet的时间
} ewfd_framework_st;

// read from local confs
extern smartlist_t *client_unit_confs;
extern ewfd_framework_st *ewfd_framework;

// init ewfd padding framework
void ewfd_framework_init(void);
void ewfd_framework_free(void);

// global timer and sending queue
extern int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti);

#endif
