#include "core/or/or.h"
#define EWFD_USE_TEMP_LOG
#include "feature/ewfd/debug.h"
#include "feature/ewfd/ewfd_conf.h"

#include "feature/ewfd/ewfd_dev.h"
#include "feature/ewfd/circuit_padding.h"
#include <stdlib.h>
#include <stdint.h>
#include "feature/ewfd/ewfd_rt.h"
#include "feature/ewfd/ewfd_op.h"

typedef struct {
	uint32_t *buffer;
	int head;
	int tail;
	int max_size;
	int size;
} ring_buffer_st;

static ring_buffer_st *create_ring_buffer(int max_size) {
	ring_buffer_st *rb = (ring_buffer_st *) malloc(sizeof(ring_buffer_st));
	rb->buffer = (uint32_t *) malloc(max_size * sizeof(uint32_t));
	rb->head = 0;
	rb->tail = 0;
	rb->max_size = max_size;
	rb->size = 0;
	return rb;
}

static void destroy_ring_buffer(ring_buffer_st *rb) {
	free(rb->buffer);
	free(rb);
}

static int ring_buffer_is_empty(ring_buffer_st *rb) {
	return (rb->size == 0);
}

static int ring_buffer_is_full(ring_buffer_st *rb) {
	return (rb->size == rb->max_size);
}

static void ring_buffer_enqueue(ring_buffer_st *rb, uint32_t data) {
	if (ring_buffer_is_full(rb)) {
		return;
	}
	rb->buffer[rb->head] = data;
	rb->head = (rb->head + 1) % rb->max_size;
	rb->size++;
}

static uint32_t ring_buffer_dequeue(ring_buffer_st *rb) {
	if (ring_buffer_is_empty(rb)) {
		return -1;
	}
	uint32_t data = rb->buffer[rb->tail];
	rb->tail = (rb->tail + 1) % rb->max_size;
	rb->size--;
	return data;
}

static uint32_t ring_buffer_peek(ring_buffer_st *rb) {
	if (ring_buffer_is_empty(rb)) {
		return -1;
	}
	uint32_t data = rb->buffer[rb->tail];
	return data;
}


static void ring_buffer_reset(ring_buffer_st *rb) {
	rb->head = rb->size;
	rb->tail = 0;
}



/** Default unit handler for dev
*/
const uint32_t SCHEDULE_TI = 200; // 200ms一次调用

ring_buffer_st *timeline_default = NULL;

static int front_timeline[] = {
	31, 93, 140, 180, 182, 206, 235, 236, 273, 296, 316, 321, 338, 349, 359, 391, 397, 412, 431, 439, 
	454, 474, 477, 496, 502, 514, 521, 536, 542, 549, 557, 565, 566, 579, 585, 586, 592, 597, 605, 607, 
	609, 620, 620, 640, 642, 643, 645, 653, 671, 696, 702, 703, 704, 710, 712, 716, 732, 737, 747, 752, 
	761, 788, 789, 803, 819, 829, 835, 837, 842, 863, 867, 870, 872, 879, 894, 902, 918, 942, 951, 956, 
	966, 976, 986, 1000, 1003, 1004, 1006, 1035, 1046, 1054, 1056, 1056, 1064, 1066, 1074, 1078, 1083, 1098, 1101, 1109, 
	1110, 1118, 1131, 1132, 1152, 1155, 1189, 1199, 1209, 1210, 1222, 1226, 1232, 1236, 1247, 1250, 1269, 1271, 1289, 1290, 
	1296, 1308, 1311, 1318, 1335, 1386, 1386, 1406, 1410, 1430, 1463, 1469, 1473, 1492, 1494, 1499, 1499, 1525, 1554, 1555, 
	1561, 1565, 1566, 1566, 1572, 1575, 1575, 1583, 1606, 1628, 1633, 1636, 1656, 1660, 1678, 1679, 1689, 1694, 1713, 1714, 
	1749, 1763, 1770, 1792, 1813, 1816, 1818, 1822, 1825, 1835, 1901, 1903, 1909, 1924, 1937, 1942, 1963, 1973, 1982, 2050, 
	2080, 2113, 2141, 2152, 2176, 2180, 2242, 2323, 2385, 2425, 2513, 2519, 2547, 2602, 2615, 2662, 2919, 3097, 3180, 3654,
};

static void dev_front_init(void) {
	timeline_default = create_ring_buffer(sizeof(front_timeline) / sizeof(int) + 1);
	int pkt = 5;
	pkt = sizeof(front_timeline) / sizeof(int);
	for(int i = 0; i < pkt; i++) {
		ring_buffer_enqueue(timeline_default, front_timeline[i]);
	}
}

/** 完整的用C实现front算法
*/
static uint64_t dev_front_on_tick(ewfd_circ_status_st *ewfd_status) {
	if (timeline_default == NULL) {
		ewfd_default_init_unit();
	}
	uint64_t ret = (uint64_t) EWFD_OP_DUMMY_PACKET << 32;
	// tor_assert(timeline_default);
	uint32_t now_ti = ewfd_status->now_ti;
	uint32_t start_ti = ewfd_status->padding_start_ti;
	uint32_t next_ti = ring_buffer_peek(timeline_default);

	if (next_ti == (uint32_t) -1) {
		ring_buffer_reset(timeline_default);
		ewfd_status->padding_start_ti = now_ti;
		return 0;
	}

	int t = 0;
	uint32_t send_ti = start_ti + next_ti;

	EWFD_LOG("[padding-unit] start-ti: %u send-ti: %u", start_ti, send_ti);

	// remove out of date packet
	while (send_ti < now_ti) {
		ring_buffer_dequeue(timeline_default);
		send_ti = start_ti + ring_buffer_peek(timeline_default);
	}

	while (send_ti < now_ti + SCHEDULE_TI && t < 5) {
		ewfd_add_dummy_packet(ewfd_status->on_circ, send_ti);
		ring_buffer_dequeue(timeline_default);
		send_ti = now_ti + ring_buffer_peek(timeline_default);
		t++;
	}
	EWFD_LOG("want to add padding packet: %d %u", t, send_ti);
	return ret | t;
}

/*
*/
uint64_t ewfd_default_schedule_unit(ewfd_circ_status_st *ewfd_status) {
	uint64_t ret = 0;

	// 如果超过一定时间没有发包就关闭padding unit
	uint32_t now_ti = ewfd_status->now_ti;
	uint32_t last_ti = ewfd_status->last_cell_ti;

	// EWFD_LOG("schedule_unit now_ti: %u, last_ti: %u", now_ti, last_ti);

	const uint32_t max_idle_ti = 2000; // 2s
	if (now_ti > last_ti + max_idle_ti) {
		uint32_t args = (ewfd_status->cur_padding_unit << 16) | EWFD_PEER_PAUSE;
		return (uint64_t) EWFD_SCHEDULE_RESET_UNIT << 32 | args;
	}

	return ret;
}

// ---------------------------
// c gan unit
// ---------------------------

static uint32_t gan_brust_gap_ms[] = {
	437, 186, 88, 13, 4, 25, 159, 28, 32, 215, 13, 6, 26, 
	176, 33, 21, 13, 17, 102, 477, 367, 91, 178, 98, 
	13, 11, 349, 72, 31, 23, 19, 10, 81, 47, 
	189, 16, 55, 5, 9, 32, 62, 22, 129, 170
};

static uint32_t gan_flow_pkts[] = {
	2, 13, 2, 2, 7, 3, 4, 2, 21, 2, 9, 4, 2, 4,
};

static void dev_gan_init(void) {
	EWFD_LOG("dev_gan_init");
}

static int add_delay_pkt = 100;

static uint64_t dev_gan_on_tick(ewfd_circ_status_st *ewfd_status) {
	// EWFD_LOG("on gan tick");
	// 1s一个delay包，延时50ms
	uint64_t now_ti = ewfd_status->now_ti;
	uint64_t last_ti = ewfd_status->last_padding_ti;
	uint64_t gap_ms = 200;
	if (last_ti + gap_ms < now_ti && add_delay_pkt > 0) {
		uint64_t send_ti = now_ti;
		send_ti += 2000; // delay 2s
		EWFD_TEMP_LOG("----------------gan add delay packet last_ti: %lu cur_ti: %lu trigger-ti: %lu", last_ti, now_ti, send_ti);
		
	#ifdef EWFD_USE_SIMPLE_DELAY
		ewfd_add_delay_packet(ewfd_status->on_circ, now_ti, send_ti, 10);
	#elif defined(EWFD_USE_ADVANCE_DELAY)
		ewfd_op_delay(ewfd_status->on_circ, now_ti, send_ti, 10);
	#endif

		// 直接发送drop包，测试功能
		// ewfd_add_dummy_packet(ewfd_status->on_circ, send_ti);
		// ewfd_paddding_op_dummy_impl((circuit_t *) ewfd_status->on_circ);
		ewfd_status->last_padding_ti = now_ti;
		--add_delay_pkt;
	}

	return 0;
}

/* 当前测试的防御
*/
// #define USE_DEV_FRONT
#define USE_DEV_GAN

uint64_t ewfd_default_init_unit(void) {
	// init current padding unit
#if defined (USE_DEV_FRONT)
	dev_front_init();
#elif defined (USE_DEV_GAN)
	dev_gan_init();
#endif
	return 0;
}

uint64_t ewfd_default_padding_unit(ewfd_circ_status_st *ewfd_status) {
#if defined (USE_DEV_FRONT)
	return dev_front_on_tick(ewfd_status);
#elif defined (USE_DEV_GAN)
	return dev_gan_on_tick(ewfd_status);
#endif
	return 0;
}
