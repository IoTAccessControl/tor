#include "feature/ewfd/ewfd.h"
#include "feature/ewfd/debug.h"
#include "feature/ewfd/utils.h"
#include "feature/ewfd/circuit_padding.h"
#include "lib/log/util_bug.h"
#include "ext/tor_queue.h"
#include "feature/ewfd/ewfd_conf.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

// eBPF code list
ewfd_client_conf_st *ewfd_client_conf = NULL;
ewfd_framework_st *ewfd_framework_instance = NULL;

typedef struct ewfd_dummy_packet_t {
	TOR_SIMPLEQ_ENTRY(ewfd_dummy_packet_t) next;
	uintptr_t on_circt;
	uint32_t insert_ti;
} ewfd_dummy_packet_st;

typedef struct ewfd_packet_queue_t {
	TOR_SIMPLEQ_HEAD(packet_simpleq_t, ewfd_dummy_packet_t) head;
	uint32_t queue_len;
} ewfd_packet_queue_st;


static void parser_client_conf(void);

/*
*/
static void init_framework_ticker(void);
static void free_framework_ticker(void);

static void init_ewfd_queues(ewfd_framework_st *framework);
static void free_ewfd_queues(ewfd_framework_st *framework);

static void on_padding_unit_tick(periodic_timer_t *timer, void *data);
static void on_padding_queue_tick(periodic_timer_t *timer, void *data);

void ewfd_framework_init(void) {
	EWFD_LOG("ewfd_padding_init");

	init_ewfd_code_cache();

	ewfd_framework_instance = (ewfd_framework_st *) tor_malloc_zero(sizeof(ewfd_framework_st));
	
	// init packet queue
	init_ewfd_queues(ewfd_framework_instance);

	parser_client_conf();

	// init_framework_ticker();
}

void start_ewfd_padding_framework(void) {
	if (ewfd_framework_instance != NULL && ewfd_framework_instance->packet_ticker == NULL) {
		init_framework_ticker();
	}
}

void ewfd_framework_free(void) {

	EWFD_LOG("ewfd_padding_free");
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

		// free_framework_ticker();
		tor_free(ewfd_framework_instance);
	}

	free_ewfd_code_cache();
}

/* 按照时间顺序来插入包
*/
int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti) {
	if (ewfd_framework_instance->dummy_packet_queue == NULL) {
		return -1;
	}

	
	if (ewfd_framework_instance->last_packet_ti == 0) {
		ewfd_framework_instance->last_packet_ti = insert_ti;
		EWFD_LOG("init_ewfd_queues start-ti: %u", ewfd_framework_instance->last_packet_ti);
	}

	ewfd_dummy_packet_st *packet = tor_malloc_zero(sizeof(ewfd_dummy_packet_st));
	packet->insert_ti = insert_ti;
	packet->on_circt = on_circ;
	ewfd_packet_queue_st *queue = (ewfd_packet_queue_st *) ewfd_framework_instance->dummy_packet_queue;
	{
		ewfd_dummy_packet_st *insert_here = NULL;
		ewfd_dummy_packet_st *cur_pkt = NULL;
		TOR_SIMPLEQ_FOREACH(cur_pkt, &queue->head, next) {
			if (cur_pkt->insert_ti > insert_ti) {
				break;
			}
			insert_here = cur_pkt;
		}

		if (insert_here == NULL) {
			TOR_SIMPLEQ_INSERT_TAIL(&queue->head, packet, next);
		} else {
			TOR_SIMPLEQ_INSERT_AFTER(&queue->head, insert_here, packet, next);
		}
		queue->queue_len++;
	}
	uint32_t gid = ewfd_get_circuit_id((circuit_t *)on_circ);
	EWFD_LOG("[%u] insert packet: %u", gid, packet->insert_ti);
	return 0;
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
	static const struct timeval gap = {0, MIN_EWFD_TICK_GAP_MS * 1000};
	// ewfd_framework_instance->padding_ticker = periodic_timer_new(tor_libevent_get_base(), &gap, 
	// 	on_padding_unit_tick, NULL);
	
	ewfd_framework_instance->packet_ticker = periodic_timer_new(tor_libevent_get_base(), &gap, 
		on_padding_queue_tick, NULL);

	ewfd_framework_instance->last_packet_ti = monotime_absolute_msec();
}

static void free_framework_ticker(void) {
	tor_assert(ewfd_framework_instance);
	periodic_timer_free(ewfd_framework_instance->padding_ticker);
}

static void init_ewfd_queues(ewfd_framework_st *framework) {
	if (framework->dummy_packet_queue == NULL) {
		framework->dummy_packet_queue = (ewfd_packet_queue_st *) tor_malloc_zero(sizeof(ewfd_packet_queue_st));
		TOR_SIMPLEQ_INIT(&framework->dummy_packet_queue->head);
	}
}

static void free_ewfd_queues(ewfd_framework_st *framework){
	ewfd_dummy_packet_st *packet;
	if (framework->dummy_packet_queue != NULL) {
		while ((packet = TOR_SIMPLEQ_FIRST(&framework->dummy_packet_queue->head)) != NULL) {
			TOR_SIMPLEQ_REMOVE_HEAD(&framework->dummy_packet_queue->head, next);
			tor_free(packet);
			// framework->dummy_packet_queue->queue_len--;
		}
		tor_free(framework->dummy_packet_queue);
		framework->dummy_packet_queue = NULL;
	}
}

static void on_padding_unit_tick(periodic_timer_t *timer, void *data) {
	// uint64_t ti = monotime_absolute_msec();
	// EWFD_LOG("on_padding_unit_tick: %d", (int)(ti / 1000));
}

void remove_remain_dummy_packets(uintptr_t on_circ) {
	tor_assert(ewfd_framework_instance);
	ewfd_packet_queue_st *queue = (ewfd_packet_queue_st *) ewfd_framework_instance->dummy_packet_queue;
	{
		ewfd_dummy_packet_st *cur_pkt = NULL;
		int all_pkt = 0;

		// remove outdated packet
		while ((cur_pkt = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL && cur_pkt->on_circt == on_circ) {
			TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
			tor_free(cur_pkt);
			queue->queue_len--;
			all_pkt++;
		}
		if (all_pkt > 0) {
			EWFD_LOG("remove_remain_dummy_packets: %d", all_pkt);
		}
	}
}


extern bool ewfd_padding_op(int op, circuit_t *circ, uint32_t delay);

/* send [last_dummy, last_dummy + GAP) 区间的包
*/
static void on_padding_queue_tick(periodic_timer_t *timer, void *data) {
	// uint64_t ti = monotime_absolute_msec();
	// EWFD_LOG("on_padding_queue_tick: %d", (int)(ti / 1000));
	tor_assert(ewfd_framework_instance);
	ewfd_packet_queue_st *queue = (ewfd_packet_queue_st *) ewfd_framework_instance->dummy_packet_queue;
	{
		ewfd_dummy_packet_st *cur_pkt = NULL;
		uint32_t cur_ti = monotime_absolute_msec();
		int expire_pkt = 0;
		
		// 如果长时间没发包，last_tick会有很大误差，因此需要修正到 [cur_ti - 500mx, cur_ti) 之间
		if ((cur_pkt = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL) {
			ewfd_framework_instance->last_packet_ti = MIN(cur_pkt->insert_ti, cur_ti);
			// 如果堆积的包太多直接忽略, insert_ti和cur_ti相差500ms以上，说明性能过查
			if (ewfd_framework_instance->last_packet_ti + MIN_EWFD_TICK_GAP_MS < cur_ti) {
				EWFD_LOG("WARNING: too many dummy packets in queue, drop these packets");
				ewfd_framework_instance->last_packet_ti = cur_ti;
			}
		}

		uint32_t range_start = ewfd_framework_instance->last_packet_ti;
		uint32_t range_end = range_start + MIN_EWFD_TICK_GAP_MS;
		uint32_t last_pkt_ti = 0;

		// remove outdated packet
		while ((cur_pkt = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL && 
			cur_pkt->insert_ti < range_start) {
			TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
			tor_free(cur_pkt);
			queue->queue_len--;

			expire_pkt++;
			EWFD_LOG("[EWFD-Dummy] remove outdated pkt: %u %u", cur_pkt->insert_ti, range_start);
			// cur_pkt = TOR_(&queue->head);
		}

		int pkt_num = 0;
		#define EWFD_OP_DUMMY_PACKET 1
		while ((cur_pkt = TOR_SIMPLEQ_FIRST(&queue->head)) != NULL) {
			if (cur_pkt->insert_ti >= range_end) {
				break;
			}
			ewfd_padding_op(EWFD_OP_DUMMY_PACKET, (circuit_t *) cur_pkt->on_circt, 0);
			pkt_num++;
			ewfd_framework_instance->all_pkt++;
			last_pkt_ti = cur_pkt->insert_ti;

			// remove sent packet
			TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
			tor_free(cur_pkt);
			queue->queue_len--;
		}
		
		uint32_t remain = 0;
		uint32_t expire = 0;
		TOR_SIMPLEQ_FOREACH(cur_pkt, &queue->head, next) {
			if (cur_pkt->insert_ti < range_end) {
				expire++;
			}
			remain++;
		}
		if (remain > 0) {
			EWFD_LOG("[EWFD-Dummy] remain: %u expire: %u len: %u tick: %u", 
				remain, expire, queue->queue_len, range_start);
		}

		// (last_ti, last_ti + MIN_EWFD_TICK_GAP_MS] 区间内的包已经发送完毕
		ewfd_framework_instance->last_packet_ti = MAX(last_pkt_ti, range_end);
		if (expire_pkt > 0 || pkt_num > 0) {
			EWFD_LOG("[EWFD-Dummy] all-send: %d send-in-tick: %d expire-pkt: %d. cur-ti: %u  send range: %u -> %u", 
				ewfd_framework_instance->all_pkt, pkt_num, expire_pkt, cur_ti, range_start, range_end);
		}
		
	}
}