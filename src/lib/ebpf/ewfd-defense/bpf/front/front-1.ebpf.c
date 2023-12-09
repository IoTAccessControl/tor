#include "../headers/ewfd.h"
#include <stdint.h>


#define SCHEDULE_TI 500
#define FRONT_DATA_STREAM_ID 1


SEC("ewfd/default")
uint64_t ewfd_default(struct ewfd_circ_status_t *status) {
	return status->padding_start_ti;
}

SEC("ewfd/front/padding/init")
uint64_t ewfd_init(void *ewfd_unit) {
	log_print("[ebpf] ewfd_init: %d\n", __LINE__);
	ebpf_init_data_stream((uint64_t) ewfd_unit, FRONT_DATA_STREAM_ID, "efwd/front/v0");
	return 0;
}


SEC("ewfd/front/padding/tick")
uint64_t ewfd_tick(struct ewfd_circ_status_t *ewfd_status) {
	log_print("[ebpf] ewfd_tick: %d\n", __LINE__);
	uint64_t ret = (uint64_t) 1 << 32;

	uint64_t ewfd_unit = ewfd_status->ewfd_unit;

	// tor_assert(timeline_default);
	uint32_t now_ti = ewfd_status->now_ti;
	uint32_t start_ti = ewfd_status->padding_start_ti;
	uint32_t next_ti = ewfd_data_stream_fetch(ewfd_unit, FRONT_DATA_STREAM_ID);

	log_print("[padding-unit] next-ti: %d\n", next_ti);

	if (next_ti == (uint32_t) -1) {
		log_print("load more data: %u\n", now_ti);
		ewfd_data_stream_load_more(ewfd_unit, FRONT_DATA_STREAM_ID);
		ewfd_status->padding_start_ti = now_ti;
		return 0;
	}

	int t = 0;
	uint32_t send_ti = start_ti + next_ti;

	log_print("[padding-unit] start-ti: %u send-ti: %u", start_ti, send_ti);

	// remove out of date packet
	while (send_ti < now_ti) {
		ewfd_data_stream_dequeue(ewfd_unit, FRONT_DATA_STREAM_ID);
		send_ti = start_ti + ewfd_data_stream_fetch(ewfd_unit, FRONT_DATA_STREAM_ID);
	}

	while (send_ti < now_ti + SCHEDULE_TI && t < 5) {
		ewfd_add_dummy_packet((void *) ewfd_status->on_circ, send_ti);
		ewfd_data_stream_dequeue(ewfd_unit, FRONT_DATA_STREAM_ID);
		send_ti = now_ti + ewfd_data_stream_fetch(ewfd_unit, FRONT_DATA_STREAM_ID);
		t++;
	}
	log_print("want to add padding packet: %d %u\n", t, send_ti);
	return ret | t;
	// return status->send_cell_cnt + (uint64_t) status->recv_cell_cnt;
}

/*
Helper, switch padding unit:
change_padding_unit_state(unit_num, state)

return state | reset
*/
SEC("ewfd/front/schedule/1")
uint64_t ewfd_schedule(struct ewfd_circ_status_t *status) {
	log_print("ewfd_schedule: %d\n", __LINE__);
	if (status->send_cell_cnt > 1000) {
		
	}
	return status->send_cell_cnt + (uint64_t) status->recv_cell_cnt;
}
