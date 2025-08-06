// local log enable/dsiable

#define EWFD_USE_TEMP_LOG
#include "feature/ewfd/debug.h"

#include "feature/ewfd/ewfd_op.h"
#include "feature/ewfd/ewfd.h"
#include "feature/ewfd/circuit_padding.h"

#include "ext/tor_queue.h"
#include "core/or/or.h"
#include "core/or/relay.h"
#include "core/or/cell_st.h"
#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/relay.h"
#include "core/or/circuitlist.h"
#include "core/or/cell_queue_st.h"
#include "core/or/circuitmux_ewfd.h"
#include "core/or/channel.h"
#include "feature/stats/rephist.h"
#include <stdint.h>
#include <string.h>
#include "core/crypto/relay_crypto.h"
#include "core/or/connection_or.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/log/util_bug.h"
#include "lib/time/compat_time.h"
#include "lib/malloc/malloc.h"
#include "core/or/command.h"
#include "core/or/scheduler.h"

#define EWFD_DELAY_MAGIC 0xcccccccc
#define EWFD_DELAY_TIMEOUT 500 // 超过500ms没处理的delay包直接丢弃

enum EWFD_DELAY_EVENT {
	EWFD_DELAY_EVENT_END = 0,
	EWFD_DELAY_EVENT_WAIT = 1,
};

typedef struct ewfd_delay_event_t {
	uint32_t magic;
	uint64_t trigger_ms;
	uintptr_t on_circ;
	uint8_t pkt_num;
	uint8_t event;
	bool is_trigger;
} __attribute__((packed)) ewfd_delay_event_st;

extern packed_cell_t* packed_cell_new(void);

static void my_pad_cell_payload(uint8_t *cell_payload, size_t data_len);
static packed_cell_t* my_copy_packed_cell(cell_t *cell, uint8_t wide_circ_ids);
static ewfd_delay_event_st* try_get_delay_packet(packed_cell_t *cell, uint8_t wide_circ_ids);
static packed_cell_t* find_next_real_packet(cell_queue_t *queue, packed_cell_t *cur_cell, uint8_t wide_circ_ids);

/*------------------*/
// private funcs
/*------------------*/

static void my_pad_cell_payload(uint8_t *cell_payload, size_t data_len) {
	size_t pad_len;
	tor_assert(cell_payload);
	tor_assert(data_len <= RELAY_PAYLOAD_SIZE);

	#define CELL_PADDING_GAP 4
	size_t offset = RELAY_HEADER_SIZE + data_len + CELL_PADDING_GAP;
	if (offset >= CELL_PAYLOAD_SIZE) {
		return;
	}

	/* Remember here that the cell_payload is the length of the header and
	* payload size so we offset it using the full length of the cell. */
	pad_len = CELL_PAYLOAD_SIZE - offset;
	crypto_fast_rng_getbytes(get_thread_fast_rng(),
							cell_payload + offset, pad_len);
}

static packed_cell_t* my_copy_packed_cell(cell_t *cell, uint8_t wide_circ_ids) {
	packed_cell_t *copy = packed_cell_new();
	/*
	注意：这里请调用自带的packed_cell_new，不然total_cells_allocated不平衡
	free的时候，--total_cells_allocated会导致溢出，从而触发OOM检查关闭flow,tor-src/src/core/or/relay.c:3300
	*/
	// packed_cell_t *copy = (packed_cell_t *) tor_malloc(sizeof(packed_cell_t));
	cell_pack(copy, cell, wide_circ_ids);
	return copy;
}

static ewfd_delay_event_st* try_get_delay_packet(packed_cell_t *cell, uint8_t wide_circ_ids) {
	// cid (u32/u16), cmd (u8), body
	uint8_t pos = wide_circ_ids ? 5 : 3;
	ewfd_delay_event_st *delay_event = (ewfd_delay_event_st *) (cell->body + pos);
	if (delay_event->magic == EWFD_DELAY_MAGIC) {
		return delay_event;
	}
	return NULL;
}

packed_cell_t* ewfd_craft_dummy_packet(circuit_t *circ) {
	cell_direction_t cell_direction = CIRCUIT_IS_ORIGIN(circ) ? CELL_DIRECTION_OUT : CELL_DIRECTION_IN;
	cell_t cell = {0};
	uint8_t wide_circ_ids = 0;

	cell.command = CELL_RELAY;

	/* create the dummy cell
		add cell header, drop
		use empty payload
	*/
	relay_header_t rh = {0};
	rh.command = RELAY_COMMAND_DROP;
	rh.stream_id = 0;
	relay_header_pack(cell.payload, &rh);
	// add random data to dummy cell
	my_pad_cell_payload(cell.payload, 0);

	if (cell_direction == CELL_DIRECTION_OUT) {
		ewfd_padding_runtime_st *ewfd_rt = ewfd_get_runtime_on_circ(circ);
		tor_assert(ewfd_rt);
		int slot = ewfd_rt->padding_unit_ctx.active_slot;
		int hopnum = ewfd_rt->padding_slots[slot]->conf->target_hopnum;
		origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
		wide_circ_ids = circ->n_chan->wide_circ_ids;
		cell.circ_id = circ->n_circ_id;
		crypt_path_t* target_hop = circuit_get_cpath_hop(origin_circ, hopnum);

		EWFD_TEMP_LOG("SEND DROP to hop: %d", hopnum);
		
		// this ciruit is not ready?
		if (target_hop == NULL) {
			// tor_assert(target_hop);

			EWFD_LOG("ERROR: Can't find target hop for hop: %d circ_id: %u", hopnum, circ->n_circ_id);
			return NULL;
		}
		relay_encrypt_cell_outbound(&cell, origin_circ, target_hop);
	} else if (cell_direction == CELL_DIRECTION_IN) {
		or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
		wide_circ_ids = or_circ->p_chan->wide_circ_ids;
		cell.circ_id = or_circ->p_circ_id;
		relay_encrypt_cell_inbound(&cell, TO_OR_CIRCUIT(circ));

		EWFD_TEMP_LOG("SEND-client DROP circ_id: %u", or_circ->p_circ_id);
	}

	return my_copy_packed_cell(&cell, wide_circ_ids);
}

static packed_cell_t* find_next_real_packet(cell_queue_t *queue, packed_cell_t *cur_cell, uint8_t wide_circ_ids) {
	packed_cell_t *next_cell = cur_cell;

	// 如果遇到了连续的delay cell，就跳过
	// remove current cell from queue
	while ((next_cell = TOR_SIMPLEQ_NEXT(next_cell, next)) != NULL) {
		if (try_get_delay_packet(next_cell, wide_circ_ids) == NULL) {
			// remove real cell
			TOR_SIMPLEQ_REMOVE_AFTER(&queue->head, cur_cell, next);
			--queue->n;
			return next_cell;
		}
		cur_cell = next_cell;
	}
	
	return NULL;
}

/*------------------*/
// public funcs
/*------------------*/

/* pop，每次调用只处理一个delay event
 n_cell 队列中减少的包的数量, 0, 1, 2 (real, delay)
[delay] 包的效果是让后面p个包延时t发送。如果队列中没有足够的包，就发送dummy包
[t=3, p=3] 1, 2, 3, [1] [3] 4, 5, 6, 7

send_state: 是否需要先切换队列
*/
packed_cell_t * ewfd_cell_queue_pop_simple_delay(cell_queue_t *queue, uint8_t wide_circ_ids, uint8_t *n_cell) {
	packed_cell_t *first_cell = TOR_SIMPLEQ_FIRST(&queue->head);
	if (first_cell == NULL) {
		return NULL;
	}
	*n_cell = 1;

	uint64_t cur_ti = monotime_absolute_msec();
	uint32_t cid = 0;
	uint8_t cmd = 0;

	// pkt detail
	#if 1
	int pos = 0;

	if (wide_circ_ids) {
		pos += 4;
		cid = ntohl(get_uint32(first_cell->body));
	} else {
		pos += 2;
		cid = ntohs(get_uint16(first_cell->body));
	}
	cmd = get_uint8(first_cell->body + pos);
	#endif

	EWFD_TEMP_LOG("[send queue poll] circ: %u cell in queue: %p cur_ti: %lu", cid, first_cell, cur_ti);

	/* packed_cell结构：
	* [1] u32 or u16, circ_id
	* [2] u8 command
	* [3] payload (real packets are encrypted)
	* 		-> [relay_header_t] + cell_payload
	*/
	ewfd_delay_event_st *delay_event = try_get_delay_packet(first_cell, wide_circ_ids);
	
	if (delay_event == NULL) { // normal cell, is not delay event
		TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
		--queue->n;
		EWFD_LOG("handle normal cell: %u wid: %d cmd: %s q-len: %d", cid, wide_circ_ids, cell_command_to_string(cmd), queue->n);
		return first_cell;
	}
	tor_assert(delay_event->pkt_num > 0);
	
	/* has delay cell
	1. 检查delay时间, [delay-1], pkt-1, pkt-2, ..., [delay-n]
		- 如果delay < cur_ti - timeout，丢弃delay包
		- 如果delay < cur_ti，就等待
		- 如果delay > cur_ti，就发送pkt_num个包
	2. 发送包, 如果包的数量不够就插入dummy包
	*/
	bool discard_delay = false;

	// Step-1: 检查delay时间
	if (delay_event->trigger_ms + EWFD_DELAY_TIMEOUT < cur_ti) { // 超时移除当前delay cell
		// 出现多个delay event堆积，就会每次移除一个delay，然后发一个real包或者一个dummy包
		EWFD_LOG("delay cell timeout: %x cur_ti: %lu trigger: %lu n-pkt: %u q-len: %d", delay_event->magic, cur_ti, 
		delay_event->trigger_ms, delay_event->pkt_num, queue->n);
		discard_delay = true;
	} else if (delay_event->trigger_ms > cur_ti) { // 需要等待，触发拥塞控制，将当前circuit inactive或者移到后面
		EWFD_LOG("delay cell wait: %x cur_ti: %lu trigger: %lu n-pkt: %u q-len: %d", delay_event->magic, cur_ti, 
		delay_event->trigger_ms, delay_event->pkt_num, queue->n);
		return NULL;
	}

	// Step-2: 发送真包，如果真包不够就发送dummy包
	// get next real cell or dummy cell
	packed_cell_t *next_cell = find_next_real_packet(queue, first_cell, wide_circ_ids);
	if (next_cell == NULL) { // send dummy packet
		next_cell = ewfd_craft_dummy_packet((circuit_t *) delay_event->on_circ);
		*n_cell = 0;
	}
	delay_event->pkt_num--;

	EWFD_TEMP_LOG("handle delay pkt: %x trigger: %lu n-pkt: %u", delay_event->magic, delay_event->trigger_ms, delay_event->pkt_num);

	// remove delay cell
	if (delay_event->pkt_num == 0 || discard_delay) {
		TOR_SIMPLEQ_REMOVE_HEAD(&queue->head, next);
		packed_cell_free(first_cell);
		--queue->n;
		*n_cell += 1;
		EWFD_TEMP_LOG("delete delay pkt circ: %u q-len: %d", cid, queue->n);
	}

	tor_assert(next_cell);

	return next_cell;
}

static void set_drop_cell(cell_t *cell) {
	relay_header_t rh = {0};
	rh.command = RELAY_COMMAND_DROP;
	rh.stream_id = 0;
	relay_header_pack(cell->payload, &rh);
	// add random data to dummy cell
	my_pad_cell_payload(cell->payload, 0);
}

static void set_encrypt_drop_cell(circuit_t *circ, cell_t *cell) {
	set_drop_cell(cell);

	cell_direction_t cell_direction = CIRCUIT_IS_ORIGIN(circ) ? CELL_DIRECTION_OUT : CELL_DIRECTION_IN;
	// encrypt
	if (cell_direction == CELL_DIRECTION_OUT) {
		ewfd_padding_runtime_st *ewfd_rt = ewfd_get_runtime_on_circ(circ);
		tor_assert(ewfd_rt);
		int slot = ewfd_rt->padding_unit_ctx.active_slot;
		int hopnum = ewfd_rt->padding_slots[slot]->conf->target_hopnum;
		origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
		cell->circ_id = circ->n_circ_id;
		crypt_path_t* target_hop = circuit_get_cpath_hop(origin_circ, hopnum);
		relay_encrypt_cell_outbound(cell, origin_circ, target_hop);
	} else if (cell_direction == CELL_DIRECTION_IN) {
		or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
		cell->circ_id = or_circ->p_circ_id;
		relay_encrypt_cell_inbound(cell, TO_OR_CIRCUIT(circ));
	}
}

/**
*
*/
bool ewfd_paddding_op_delay_impl(circuit_t *circ, uint32_t trigger_ms, uint32_t pkt_num) {
	ewfd_delay_event_st delay_event = {0};
	delay_event.magic = EWFD_DELAY_MAGIC;
	delay_event.trigger_ms = trigger_ms;
	delay_event.pkt_num = pkt_num;
	delay_event.on_circ = (uintptr_t) circ;
	delay_event.is_trigger = false;

	channel_t *chan; /* where to send the cell */
	cell_direction_t cell_direction;
	streamid_t on_stream = 0;

	cell_t cell = {0};

	cell_queue_t *queue;
	circuitmux_t *cmux = NULL;
	bool is_origin = false;

	cell.command = CELL_RELAY;
	if (CIRCUIT_IS_ORIGIN(circ)) {
		// tor_assert(cpath_layer);
		cell.circ_id = circ->n_circ_id;
		cell_direction = CELL_DIRECTION_OUT;
		chan = circ->n_chan;
		queue = &circ->n_chan_cells;
		is_origin = true;
	} else {
		// tor_assert(! cpath_layer);
		cell.circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
		cell_direction = CELL_DIRECTION_IN;
		chan = TO_OR_CIRCUIT(circ)->p_chan;
		queue = &TO_OR_CIRCUIT(circ)->p_chan_cells;
	}
	cmux = chan->cmux;
	memcpy(cell.payload, &delay_event, sizeof(delay_event));

	EWFD_TEMP_LOG("[EWFD-Delay] want to send delay packet: %lu n-pkt: %u wd: %d q-len: %d %s: %u", delay_event.trigger_ms, 
		delay_event.pkt_num, chan->wide_circ_ids, queue->n, is_origin ? "orgin-circ" : "or-circ", ewfd_get_circuit_id(circ));
	// circuitmux_show_info(cmux);

// 调试阶段，调用系统函数发送drop包，确保delay添加的dummy包是正确的
#if 0 // lev-1: 系统发送函数
	set_drop_cell(&cell);
	crypt_path_t* target_hop = NULL;
	if (CIRCUIT_IS_ORIGIN(circ)) {
		ewfd_padding_runtime_st *ewfd_rt = ewfd_get_runtime_on_circ(circ);
		tor_assert(ewfd_rt);
		int slot = ewfd_rt->padding_unit_ctx.active_slot;
		int hopnum = ewfd_rt->padding_slots[slot]->conf->target_hopnum;
		target_hop = circuit_get_cpath_hop(TO_ORIGIN_CIRCUIT(circ), hopnum);
	}
	
	// relay_send_command_from_edge(0, circ, RELAY_COMMAND_DROP, NULL, 0, target_hop);
	circuit_package_relay_cell(&cell, circ, cell_direction, target_hop, on_stream, "efwd_op.c", __LINE__);
	return true;
#endif 
#if 0 // lev-2: 自己组装包，调用系统的发送
	set_encrypt_drop_cell(circ, &cell);
	append_cell_to_circuit_queue(circ, chan, &cell, cell_direction, on_stream);
#endif 
#if 0 // lev-3: 自己组装包，直接发送 （漏洞原因，没有调用自带的packed_cell alloc）
	packed_cell_t *drop = ewfd_craft_dummy_packet(circ);
	cell_queue_append(queue, drop);
	update_circuit_on_cmux(circ, cell_direction);
	scheduler_channel_has_waiting_cells(chan);
	return true;
#endif

	// 为了避免delay_event内容被加密，所以直接加到队列
	append_cell_to_circuit_queue(circ, chan, &cell, cell_direction, on_stream);
	return true;
}

bool ewfd_paddding_op_delay_notify_impl(circuit_t *circ) {
	channel_t *chan = NULL;

	if (CIRCUIT_IS_ORIGIN(circ)) {
		// tor_assert(cpath_layer);
		chan = circ->n_chan;
	} else {
		chan = TO_OR_CIRCUIT(circ)->p_chan;
	}

	scheduler_channel_has_waiting_cells(chan);

	EWFD_TEMP_LOG("active delay circ: %u", ewfd_get_circuit_id(circ));
}

bool ewfd_paddding_op_dummy_impl(circuit_t *circ) {
	ewfd_padding_runtime_st *ewfd_rt = ewfd_get_runtime_on_circ(circ);
	tor_assert(ewfd_rt);
	int slot = ewfd_rt->padding_unit_ctx.active_slot;
	int hopnum = ewfd_rt->padding_slots[slot]->conf->target_hopnum;
	crypt_path_t *target_hop = NULL;
	if (CIRCUIT_IS_ORIGIN(circ)) {
		target_hop = circuit_get_cpath_hop(TO_ORIGIN_CIRCUIT(circ), hopnum);
		if (target_hop == NULL) {
			EWFD_LOG("ERROR: Can't find target hop for hop: %d", hopnum);
			return false;
		}
	}
	rep_hist_padding_count_write(PADDING_TYPE_DROP);
	return relay_send_command_from_edge(0, circ, RELAY_COMMAND_DROP, NULL, 0, target_hop);
}

bool ewfd_paddding_op_delay_gap_impl(circuit_t *circ, uint32_t trigger_ms, uint32_t pkt_num) {
	return circuitmux_set_advance_delay(circ, trigger_ms, pkt_num);
}

bool ewfd_padding_trigger_inactive_circ(circuit_t *circ, uint64_t tick_ms) {
	return circuitmux_trigger_inactive_circ(circ, tick_ms);
}

/* 
* ------------------------------------------------------------
*  统一调度选取chan发送
* ------------------------------------------------------------
*/
