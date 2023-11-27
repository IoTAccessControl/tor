#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "libebpf.h"
#include "ebpf_code.h"
#include "ewfd_api.h"
#include "ewfd_test.h"
#include <unistd.h>

#define TEST_BPF_CODE ewfd_default_defense
#define TEST_BPF_SIZE sizeof(TEST_BPF_CODE) - 1

static int run_ebpf_code(const char *code, size_t code_len, void *mem, size_t mem_len);


#define CODE_LEN(code) (sizeof(code) - 1)

struct mem {
	uint64_t val;
} m;

char *errmsg;

typedef struct ewfd_circ_status_t {
	uint64_t ctx; // ewfd context

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

int test_ewfd_code(void) {
	int res = 0;

	printf("ewfd run test units----------------\n");

	struct ewfd_unit_t *ctx = ewfd_unit_new();

	ewfd_circ_status_st status = {0};
	status.ctx = (uint64_t) ctx;
	status.send_cell_cnt = 1;
	status.recv_cell_cnt = 2;
	// status.padding_start_ti = 0;

	printf("padding start ti: %d\n", status.padding_start_ti);

	int tick = 0;
	
	// init
	// res = ewfd_init_front_unit(ctx, &status, sizeof(status));
	// assert(res == 0);

	res = ewfd_init_wpfpad_unit(ctx, &status, sizeof(status));
	assert(res == 0);

	while (tick < 1000) {
		printf("tick: %d\n", tick);

		// run tick
		// res = ewfd_run_front_unit(ctx, &status, sizeof(status));
		// assert(res == 0);

		res = ewfd_run_wpfpad_unit(ctx, &status, sizeof(status));
		assert(res == 0);

		tick++;

		status.now_ti += 200;
		usleep(100);
	}
	
	ewfd_unit_clear(ctx);
	return 0;
}

static int run_ebpf_code(const char *code, size_t code_len, void *mem, size_t mem_len) {
	uint64_t res = 0, ret_code = 0;

	// using ubpf jit for x86_64 and arm64
	struct ebpf_vm *vm = ebpf_create();

	res = ebpf_load(vm, code, code_len, &errmsg);
	if (res != 0) {
		fprintf(stderr, "Failed to load: %s\n", errmsg);
		goto error;
	}

	// EBPF_OP_CALL
	printf("code len: %ld mem size: %ld\n", code_len, mem_len);

	res = ebpf_exec(vm, mem, mem_len, &ret_code);
	if (res != 0) {
		fprintf(stderr, "Failed to exec: %s\n", errmsg);
		goto error;
	}
	printf("ret = %ld\n", ret_code);
	ebpf_destroy(vm);
	return 0;
error:
	// printf("error: %s %p\n", errmsg, errmsg);
	// if (errmsg) free(errmsg);
	ebpf_destroy(vm);
	return -1;
}

#include "map_test.h"
int main(int agrc, char *argv[]) {
	printf("hello ebpf\n");

	printf("\n/-------------------------------------------------\n");
	printf("test basic ringbuffer ewfd extension\n");
	printf("/-------------------------------------------------\n");
	assert(run_ebpf_code(TEST_BPF_CODE, TEST_BPF_SIZE, &m, sizeof(struct mem)) == 0);
	assert(test_ewfd_code() == 0);

	printf("\n/-------------------------------------------------\n");
	printf("test basic hashmap\n");
	printf("/-------------------------------------------------\n");
	test_basic_hashmap();

	return 0;
}
