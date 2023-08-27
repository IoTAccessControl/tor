#pragma once

#include <stdint.h>


#define SEC(name) __attribute__((section(# name)))


#define DECLARE_EWFD_TIMELINE(name, UUID) \
	const int EWFD_TIMELINE_##name = UUID;

typedef struct ewfd_circ_status_t {
	uint64_t ewfd_unit;
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

// helpers

static long (*ebpf_log_print)(const char *fmt, uint32_t fmt_size, ...) = (void *) 1;
#define log_print(fmt, ...)				\
({							\
	char ____fmt[] = fmt;	\
	ebpf_log_print(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

// helpers for ewfd packet/schedule
static int (*ewfd_add_dummy_packet)(void *circut, uint32_t send_ti) = (void *) 6;

// helpers for data stream
static int (*ebpf_init_data_stream)(uint64_t ewfd_unit, int map_idx, const char *data_stream_file) = (void *) 11;
static int (*ewfd_data_stream_load_more)(uint64_t ewfd_unit, uint32_t data_stream_fd) = (void *) 12;
static uint32_t (*ewfd_data_stream_fetch)(uint64_t ewfd_unit, uint32_t data_stream_fd) = (void *) 13;
static int (*ewfd_data_stream_dequeue)(uint64_t ewfd_unit, uint32_t data_stream_fd) = (void *) 14;
