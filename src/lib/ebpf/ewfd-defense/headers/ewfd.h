#pragma once

#include <stdint.h>


#define DECLARE_EWFD_TIMELINE(name, UUID) \
	const int EWFD_TIMELINE_##name = UUID;

typedef struct ewfd_circ_status_t {
	// __IN
	// uint32_t last_delay_ti;
	uint32_t padding_start_ti; // first padding init time
	uint32_t last_padding_ti;  // previous padding unit exec time
	uint32_t last_cell_ti;     // last cell send/receive time
	uint32_t now_ti;
	
	uintptr_t on_circ;

	uint32_t send_cell_cnt;
	uint32_t recv_cell_cnt;

	// command 
	uint8_t cur_padding_unit;
	uint8_t last_relay_cmd;
	uint8_t current_relay_cmd;

	// __OUT 
	uint32_t next_tick;
} __attribute__((packed, aligned(4))) ewfd_circ_status_st;