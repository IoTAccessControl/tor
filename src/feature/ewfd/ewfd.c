#include "lib/smartlist_core/smartlist_core.h"
#include "lib/time/compat_time.h"
#include <stdio.h>
#define EWFD_USE_TEMP_LOG
#include "feature/ewfd/debug.h"

// 单元测试
// /tor-src/src/test/test circuitmux_ewfd/event_queue_poll 
// #define EWFD_UNITEST_TEST_PRIVATE
#include "feature/ewfd/ewfd.h"
#include "feature/ewfd/ewfd_ticker.h"
#include "feature/ewfd/utils.h"
#include "feature/ewfd/circuit_padding.h"
#include "lib/log/util_bug.h"
#include "core/or/or.h"
#include "core/or/channel.h"
#include "core/or/cell_st.h"
#include "ext/tor_queue.h"
#include "feature/ewfd/ewfd_conf.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "feature/ewfd/ewfd_op.h"
#include "feature/ewfd/ebpf_api.h"


#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


// eBPF code list
ewfd_client_conf_st *ewfd_client_conf = NULL;
ewfd_framework_st *ewfd_framework_instance = NULL;

enum EWFD_OP_TYPE {
	EWFD_OP_DUMMY = 0,
	// simple delay
	EWFD_OP_DELAY = 1,
	// advance delay by set gap
	EWFD_OP_DELAY_GAP = 2,
	EWFD_OP_NOTIFY = 3,

};

enum EWFD_NOTIFY_REASON {
	EWFD_NOTIFY_CIRC_ACTIVE = 1,
	EWFD_NOFITY_CIRC_END = 2,
};

// delay/dummy全部操作的参数都放在这struct里
typedef struct ewfd_op_event_t {
	TOR_SIMPLEQ_ENTRY(ewfd_op_event_t) next;
	uintptr_t on_circ;
	uint64_t insert_ti;
	uint32_t event_id;
	// other 
	union {
		struct {
			uint32_t delay_ms; // 延迟时间
			uint32_t pkt_num; // 发送包
		} delay_event;
		struct {
			uint8_t reason;  // reason 1: delay 2: end
		} notify_event;
	};
	uint8_t ewfd_op;
} ewfd_op_event_st;

typedef struct ewfd_event_queue_t {
	TOR_SIMPLEQ_HEAD(packet_simpleq_t, ewfd_op_event_t) head;
	uint32_t queue_len;
} ewfd_event_queue_st;

// put in queue
struct ewfd_delay_cell_t;
typedef struct ewfd_delay_entry_t {
	TOR_SIMPLEQ_ENTRY(ewfd_delay_entry_t) next;
	struct ewfd_delay_cell_t *entry;
} ewfd_delay_entry_st;

static void parser_client_conf(void);

/*
*/
static void init_framework_ticker(void);
static void free_framework_ticker(void);

/*
delay/dummy op：用一个队列还是2个队列？
可以共用一个队列：一般同时只会用一个算法。启动dummy，就不会再启用delay了。
*/
static void init_ewfd_queues(ewfd_framework_st *framework);
static void free_ewfd_queues(ewfd_framework_st *framework);

// 固定GAP (EWFD_EVENT_QUEUE_TICK) 触发事件队列
void on_event_queue_tick(periodic_timer_t *timer, void *data);

static int ewfd_add_to_event_queue(ewfd_op_event_st *event);
static bool handle_one_event(ewfd_op_event_st *event);
static const char* event_op_to_str(ewfd_op_event_st *event);

static uint32_t total_event_alloc = 0;

static inline ewfd_op_event_st *alloc_ewfd_event(uintptr_t on_circ, uint64_t insert_ti, uint8_t ewfd_op) {
	total_event_alloc++;
	ewfd_op_event_st *event = tor_malloc_zero(sizeof(ewfd_op_event_st));
	event->on_circ = on_circ;
	event->ewfd_op = ewfd_op;
	event->insert_ti = insert_ti;
	event->event_id = total_event_alloc; // for debug
	return event;
}

static inline void free_ewfd_event(ewfd_op_event_st *event) {
	total_event_alloc--;
	tor_free(event);
}

static inline void ewfd_event_queue_remove_first(ewfd_event_queue_st *queue, bool free_event) {
	ewfd_op_event_st *event = TOR_SIMPLEQ_FIRST(&queue->head);
	if (event != NULL) {
		TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
		queue->queue_len--;
		if (free_event) {
			free_ewfd_event(event);
		}
	}
}

void ewfd_framework_init(void) {
	EWFD_LOG("ewfd_padding_init");

	init_ewfd_code_cache();

	ewfd_framework_instance = (ewfd_framework_st *) tor_malloc_zero(sizeof(ewfd_framework_st));
	
	// init event queue
	init_ewfd_queues(ewfd_framework_instance);

	parser_client_conf();
}

void start_ewfd_padding_framework(void) {
	if (ewfd_framework_instance != NULL && ewfd_framework_instance->packet_ticker == NULL) {
		init_framework_ticker();
	}
}

void ewfd_framework_free(void) {
	EWFD_LOG("ewfd_framework_free");
	free_framework_ticker();
	if (ewfd_client_conf != NULL) {
		if (ewfd_client_conf->client_unit_confs != NULL) {
			SMARTLIST_FOREACH(ewfd_client_conf->client_unit_confs,
				ewfd_padding_conf_st *,
				conf, tor_free(conf));
			smartlist_free(ewfd_client_conf->client_unit_confs);
		}
		tor_free(ewfd_client_conf);
	}

	if (ewfd_framework_instance != NULL) {
		// free queue
		free_ewfd_queues(ewfd_framework_instance);

		tor_free(ewfd_framework_instance);
	}

	free_ewfd_code_cache();
	// assert(total_ewfd_timer == 0);
	EWFD_LOG("ewfd_framework_free total timer: %d released timer: %d", total_ewfd_timer, released_ewfd_timer);
}

static void parser_client_conf(void) {
	if (ewfd_client_conf == NULL) {
		ewfd_client_conf = tor_malloc_zero(sizeof(ewfd_client_conf_st));
	}
	if (ewfd_client_conf->client_unit_confs == NULL) {
		ewfd_client_conf->client_unit_confs = smartlist_new();
	}
	/* schedule unit和padding unit的uuid不能重复
	*/
	ewfd_padding_conf_st *padding_unit = demo_get_front_padding_unit_conf();
	ewfd_padding_conf_st *schedule_unit = demo_get_front_schedule_unit_conf();

	tor_assert(padding_unit);
	tor_assert(schedule_unit);

	smartlist_add(ewfd_client_conf->client_unit_confs, padding_unit);
	smartlist_add(ewfd_client_conf->client_unit_confs, schedule_unit);

	ewfd_client_conf->active_schedule_slot = 0;
	ewfd_client_conf->active_padding_slot = 0;

	ewfd_client_conf->need_reload = true;
}

static void init_framework_ticker(void) {
	static const struct timeval gap = {0, EWFD_EVENT_QUEUE_TICK_MS * 1000};
	
	ewfd_framework_instance->packet_ticker = periodic_timer_new(tor_libevent_get_base(), &gap, 
		on_event_queue_tick, NULL);

	ewfd_framework_instance->last_event_ti = monotime_absolute_msec();
}

static void free_framework_ticker(void) {
	if (ewfd_framework_instance != NULL && ewfd_framework_instance->packet_ticker != NULL) {
		periodic_timer_free(ewfd_framework_instance->packet_ticker);
	}
}

static void init_ewfd_queues(ewfd_framework_st *framework) {
	if (framework->ewfd_event_queue == NULL) {
		framework->ewfd_event_queue = (ewfd_event_queue_st *) tor_malloc_zero(sizeof(ewfd_event_queue_st));
		TOR_SIMPLEQ_INIT(&framework->ewfd_event_queue->head);
	}
}

static void free_ewfd_queues(ewfd_framework_st *framework){
	ewfd_op_event_st *event;
	if (framework->ewfd_event_queue != NULL) {
		while ((event = TOR_SIMPLEQ_FIRST(&framework->ewfd_event_queue->head)) != NULL) {
			TOR_SIMPLEQ_REMOVE_HEAD(&framework->ewfd_event_queue->head, next);
			framework->ewfd_event_queue->queue_len--;
			tor_free(event);
		}
		tor_free(framework->ewfd_event_queue);
	}
}


// --------------------------------------------------------------
// ewfd ebpf api 
// --------------------------------------------------------------

void ewfd_remove_remain_events(uintptr_t on_circ) {
	if (ewfd_framework_instance == NULL) { 	// tor is free
		return;
	}
	ewfd_event_queue_st *queue = (ewfd_event_queue_st *) ewfd_framework_instance->ewfd_event_queue;
	{
		int del_pkt = 0;
		ewfd_op_event_st *cur_event = TOR_SIMPLEQ_FIRST(&queue->head);
		ewfd_op_event_st *prev_event = NULL;

		// remove outdated event
		while (cur_event != NULL) {
			
			if (cur_event->on_circ == on_circ) { // delete one
				// printf("delete event: %p eid:%d circ:%p\n", cur_event, cur_event->event_id, cur_event->on_circ);
				ewfd_op_event_st *next_event = TOR_SIMPLEQ_NEXT(cur_event, next);
				if (prev_event == NULL) { // is header
					TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
				} else {
					TOR_SIMPLEQ_REMOVE_AFTER(&queue->head, prev_event, next);
				}
				free_ewfd_event(cur_event);
				queue->queue_len--;
				del_pkt++;
				cur_event = next_event;
			} else {
				prev_event = cur_event;
				cur_event = TOR_SIMPLEQ_NEXT(cur_event, next);
			}
		}
		// printf("queue len: %d remove: %d\n", queue->queue_len, del_pkt);

		if (del_pkt > 0) {
			EWFD_LOG("remove events: %d", del_pkt);
		}
	}
}

// pass unit test
int ewfd_get_event_num(uintptr_t on_circ) {
	if (ewfd_framework_instance == NULL) {
		return 0;
	}
	/* TODO: 改成hashmap读，单独维护每个circ每类包的数量
	*/
	ewfd_event_queue_st *queue = (ewfd_event_queue_st *) ewfd_framework_instance->ewfd_event_queue;
	int remain = 0;

	ewfd_op_event_st *cur_event;
	TOR_SIMPLEQ_FOREACH(cur_event, &queue->head, next) {
		if (cur_event->on_circ == on_circ) {
			remain++;
		}
	}

	// printf("queue len: %d remain: %d\n", queue->queue_len, remain);

	return remain;
}

/* 按照时间顺序来插入包
*/
int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti) {
	ewfd_op_event_st *event = alloc_ewfd_event(on_circ, insert_ti, EWFD_OP_DUMMY);

	// EWFD_TEMP_LOG("circ: %u insert dummy event: %lu", ewfd_get_circuit_id((circuit_t *)on_circ), event->insert_ti);

	return ewfd_add_to_event_queue(event);
}

int ewfd_add_delay_packet(uintptr_t on_circ, uint32_t insert_ti, uint32_t delay_to_ms, uint32_t pkt_num) {
	/*
	1. 添加一个delay event, 阻塞当前队列
	2. 添加一个delay notify event, 唤醒当前队列
	*/
	ewfd_op_event_st *delay_event = alloc_ewfd_event(on_circ, insert_ti, EWFD_OP_DELAY);
	delay_event->delay_event.delay_ms = delay_to_ms;
	delay_event->delay_event.pkt_num = pkt_num;
	int ret = ewfd_add_to_event_queue(delay_event);

	ewfd_op_event_st *notify_event = alloc_ewfd_event(on_circ, delay_to_ms, EWFD_OP_NOTIFY);
	notify_event->notify_event.reason = EWFD_NOTIFY_CIRC_ACTIVE;
	ret &= ewfd_add_to_event_queue(notify_event);

	return ret;
}

int ewfd_op_delay(uintptr_t on_circ, uint32_t insert_ti, uint32_t delay_ms, uint32_t pkt_num) {
	// set circ policy
	ewfd_op_event_st *delay_event = alloc_ewfd_event(on_circ, insert_ti, EWFD_OP_DELAY_GAP);
	delay_event->delay_event.delay_ms = delay_ms;
	delay_event->delay_event.pkt_num = pkt_num;
	return ewfd_add_to_event_queue(delay_event);
}

// --------------------------------------------------------------
// End ewfd ebpf api 
// --------------------------------------------------------------

/* send [last_dummy, last_dummy + GAP) 区间的包
*/
static int tick = 0;
void on_event_queue_tick(periodic_timer_t *timer, void *data) {
	tor_assert(ewfd_framework_instance);

	uint64_t cur_ti = monotime_absolute_msec();

#ifdef EWFD_UNITEST_TEST_PRIVATE
	if (data != NULL) {
		cur_ti = *(uint64_t *) data;
	}
#endif
	
	/* 每次处理，(上次处理到的时间戳， cur_ti] 之间的包
	*/
	ewfd_event_queue_st *queue = (ewfd_event_queue_st *) ewfd_framework_instance->ewfd_event_queue;
	{
		ewfd_op_event_st *cur_event = NULL;
		int expire_event = 0;
		
		// 如果长时间没发包，last_tick会有很大误差，因此需要修正到 [cur_ti - MAX_GAP (500ms), cur_ti) 之间
		if ((cur_event = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL) {
			ewfd_framework_instance->last_event_ti = MIN(cur_event->insert_ti, cur_ti);
			// 如果堆积的包太多直接忽略, insert_ti和cur_ti相差500ms以上，说明性能过差
			if (ewfd_framework_instance->last_event_ti + MAX_EWFD_TICK_GAP_MS < cur_ti) {
				EWFD_LOG("WARNING: too many dummy packets in queue, drop these packets");
				ewfd_framework_instance->last_event_ti = cur_ti - MAX_EWFD_TICK_GAP_MS;
			}
		}

		uint64_t range_start = ewfd_framework_instance->last_event_ti;
		uint64_t range_end = cur_ti;
		uint64_t last_event_ti = 0;

		#ifdef EWFD_UNITEST_TEST_PRIVATE
			printf("on_event_queue_tick cur_ti:%lu range:'%lu -> %lu'\n",  cur_ti, range_start, range_end);
		#endif // EWFD_UNITEST_TEST_PRIVATE

		// remove outdated event
		// 删除 (-0, cur_ti - MAX_GAP (500ms)] 之间的包
		while ((cur_event = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL && 
			cur_event->insert_ti < range_start) {
			EWFD_LOG("[EWFD-Event] remove outdated event id: %d %lu %lu", cur_event->event_id, cur_event->insert_ti, range_start);
			
			ewfd_event_queue_remove_first(queue, true);
			expire_event++;
		}

		// 处理（last_pkt_ti, cur_ti] 区间内的包
		int event_num = 0; // dummy pkt num
		int loop = 5;
		while ((cur_event = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL) {
			if (cur_event->insert_ti > range_end) {
				break;
			}
			// EWFD_TEMP_LOG("[delay-event] step:process_one_event circ:%d ev-id:%d range:'%lu->%lu' insert-ti:%lu remain:%d all:%d tick:%d", 
			// 	ewfd_get_circuit_id((circuit_t *) cur_event->on_circ), cur_event->event_id,
			// 	range_start, range_end,
			// 	cur_event->insert_ti, ewfd_get_event_num(cur_event->on_circ), 
			// 	ewfd_framework_instance->ewfd_event_queue->queue_len, tick++);
			
			// 没处理完的保存在队列
			bool is_processed = handle_one_event(cur_event);
			
			// printf("is_processed: %d tick: %lu want: %lu on_circ: %p event_id: %d\n", is_processed, cur_ti, cur_event->insert_ti, cur_event->on_circ, cur_event->event_id);

			if (is_processed) {
				last_event_ti = cur_event->insert_ti;
				event_num++;
				ewfd_event_queue_remove_first(queue, true);
			} 
			else {
				// 延期事件，加到尾部
				// 是否需要按照时间排序？
				cur_event->insert_ti += EWFD_EVENT_QUEUE_TICK_MS;
				ewfd_event_queue_remove_first(queue, false);
				EWFD_LOG("[delay-event] step:readd_event circ:%d id:%d insert-ti:%lu cur_ti:%lu", 
					ewfd_get_circuit_id((circuit_t *) cur_event->on_circ), cur_event->event_id, cur_event->insert_ti, cur_ti);
				
				// printf("delay event: %lu id:%d\n", cur_event->insert_ti, cur_event->event_id);
				// modify ti and reinsert
				ewfd_add_to_event_queue(cur_event);
			}
			// if (--loop <= 0) {
			// 	break;
			// }
		}

		uint32_t remain = 0;
		uint32_t expire = 0;
		TOR_SIMPLEQ_FOREACH(cur_event, &queue->head, next) {
			if (cur_event->insert_ti < range_end) {
				expire++;
			}
			remain++;
		}
		if (remain > 0) {
			EWFD_TEMP_LOG("[EWFD-Event] remain: %u expire: %u len: %u tick: %lu", 
				remain, expire, queue->queue_len, range_start);
		}

		// (last_ti, last_ti + EWFD_EVENT_QUEUE_TICK_MS] 区间内的包已经发送完毕
		ewfd_framework_instance->last_event_ti = MAX(last_event_ti, range_end);
		if (expire_event > 0 || event_num > 0) {
			EWFD_TEMP_LOG("[EWFD-Event] all-event: %d dummy: %d process-in-tick: %d expire-event: %d cur-ti: %lu  process range: %lu -> %lu", 
				ewfd_framework_instance->ewfd_event_queue->queue_len, ewfd_framework_instance->all_dummy_pkt, event_num, 
				expire_event, cur_ti, range_start, range_end);
		}
	}
}

static int ewfd_add_to_event_queue(ewfd_op_event_st *event) {
	if (ewfd_framework_instance->ewfd_event_queue == NULL) {
		return -1;
	}
	// 初始化 event ti，防止第一个event因超时被丢
	if (ewfd_framework_instance->last_event_ti == 0) {
		ewfd_framework_instance->last_event_ti = event->insert_ti;
	}

	ewfd_event_queue_st *queue = (ewfd_event_queue_st *) ewfd_framework_instance->ewfd_event_queue;
	{
		ewfd_op_event_st *insert_here = NULL;
		ewfd_op_event_st *cur_event = NULL;
		TOR_SIMPLEQ_FOREACH(cur_event, &queue->head, next) {
			if (cur_event->insert_ti >= event->insert_ti) {
				break;
			}
			insert_here = cur_event;
		}

		if (insert_here == NULL) {
			TOR_SIMPLEQ_INSERT_HEAD(&queue->head, event, next);
		} else {
			TOR_SIMPLEQ_INSERT_AFTER(&queue->head, insert_here, event, next);
		}
		queue->queue_len++;
	}

#ifdef EWFD_UNITEST_TEST_PRIVATE
	printf("ewfd_add_to_event_queue circ-p:%p circ:%u ev-id:%d insert-ti:%lu remain:%d\n", 
		event->on_circ,
		ewfd_get_circuit_id((circuit_t *) event->on_circ), event->event_id,
		event->insert_ti, queue->queue_len);

	// for each dump insert_ti
	printf("\t-> queue: ");
	ewfd_op_event_st *debug_event = NULL;
	TOR_SIMPLEQ_FOREACH(debug_event, &queue->head, next) {
		printf(" %d:%lu ", debug_event->event_id, debug_event->insert_ti);
	}
	printf("\n");
#else
	// EWFD_TEMP_LOG("[delay-event] step:add_to_queue circ:%d ev-id:%d insert-ti:%lu remain:%d", 
	// 	ewfd_get_circuit_id((circuit_t *) event->on_circ), event->event_id,
	// 	event->insert_ti, ewfd_get_event_num(event->on_circ));
#endif // EWFD_UNITEST_TEST_PRIVATE

	return 0;
}

static bool handle_one_event(ewfd_op_event_st *cur_event) {
	EWFD_TEMP_LOG("[delay-event] step:handle_one_event ti:%lu op:%s cur_ti:%lu id:%d", cur_event->insert_ti, 
			event_op_to_str(cur_event), monotime_absolute_msec(), cur_event->event_id);

	circuit_t * cur_circ = (circuit_t *) cur_event->on_circ;
	if (!is_valid_circuit(cur_event->on_circ)) {
		return true;
	}

	if (cur_event->ewfd_op == EWFD_OP_DUMMY) {
		if (ewfd_paddding_op_dummy_impl(cur_circ)) {
			ewfd_framework_instance->all_dummy_pkt++;
		}
	} else if (cur_event->ewfd_op == EWFD_OP_DELAY) {
		ewfd_paddding_op_delay_impl(cur_circ, cur_event->delay_event.delay_ms, cur_event->delay_event.pkt_num);
	} else if (cur_event->ewfd_op == EWFD_OP_NOTIFY) {
		if (cur_event->notify_event.reason == EWFD_NOTIFY_CIRC_ACTIVE) {
			ewfd_paddding_op_delay_notify_impl(cur_circ);
		} else if (cur_event->notify_event.reason == EWFD_NOFITY_CIRC_END) {

		}
	} else if (cur_event->ewfd_op == EWFD_OP_DELAY_GAP) {

	#ifdef EWFD_UNITEST_TEST_PRIVATE
		static int test_wait_num = 0;
		test_wait_num++;
		printf("handle event test_wait_num: %d\n", test_wait_num);
		// 每个包等待3次
		if (test_wait_num < 3) {
			return false;
		} else {
			test_wait_num = 0;
			return true;
		}
	#endif

		// 未发送完，需要等待
		bool should_wait = ewfd_paddding_op_delay_gap_impl(cur_circ, cur_event->delay_event.delay_ms, cur_event->delay_event.pkt_num);
		if (should_wait) {
			return false;
		}
	} else {
		EWFD_LOG("ERROR: unknow ewfd op: %d", cur_event->ewfd_op);
		tor_assert(false);
	}
	return true;
}

static const char* event_op_to_str(ewfd_op_event_st *event) {
	switch (event->ewfd_op) {
		case EWFD_OP_DUMMY:
			return "EWFD_OP_DUMMY";
		case EWFD_OP_DELAY:
			return "EWFD_OP_DELAY";
		case EWFD_OP_DELAY_GAP:
			return "EWFD_OP_DELAY_GAP";
		case EWFD_OP_NOTIFY: {
			if (event->notify_event.reason == EWFD_NOTIFY_CIRC_ACTIVE)
				return "EWFD_NOTIFY_CIRC_ACTIVE";
			else if (event->notify_event.reason == EWFD_NOFITY_CIRC_END)
				return "EWFD_NOFITY_CIRC_END";
			else
				return "EWFD_OP_NOTIFY";
		}
		default:
			return "EWFD_OP_UNKNOWN";
	}
	return "";
}