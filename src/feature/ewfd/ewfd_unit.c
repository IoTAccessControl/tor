
#include "feature/ewfd/ewfd_unit.h"
#include "core/or/or.h"
#include "feature/ewfd/circuit_padding.h"
#include "feature/ewfd/debug.h"
#include "feature/ewfd/ewfd_helper.h"
#include "lib/ebpf/ebpf_vm.h"
#include "lib/ebpf/libebpf.h"
#include "lib/ebpf/ewfd-defense/src/ewfd_api.h"
#include "lib/log/util_bug.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// extern int ebpf_exec(const struct ebpf_vm* vm, void* mem, size_t mem_len,
// uint64_t* bpf_return_value);

extern int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti);

/*
log:
schedule_switch:
dummy_packet:
*/
static long helper_ebpf_helper_log_print_id = 1;
// helper for efwd
static long helper_test_ewfd_add_dummy_packet_id = 6;

static void add_ewfd_tor_helpers(struct ebpf_vm *vm);
static uint64_t helper_ebpf_log_print(const char *fmt, uint32_t fmt_size, ...);
static uint64_t helper_ewfd_add_dummy_packet(uint64_t ptr, uint64_t tick);

ewfd_unit_st *init_ewfd_unit(struct ewfd_padding_conf_t *conf) {
	ewfd_unit_st *unit = ewfd_unit_new();
	char *err_msg = NULL;
	int res = 0;

	add_ewfd_tor_helpers(unit->vm);

#define EBPF_VM_ERR(res) \
	if (res != 0) { \
		EWFD_LOG("failed to load ewfd code: %s", err_msg); \
		free(err_msg); \
		return NULL; \
	}

	if (conf->init_code != NULL) {
		res = ebpf_load(unit->vm, conf->init_code->code, conf->init_code->code_len,
			&err_msg);
		EBPF_VM_ERR(res);

		if (conf->use_jit) {
			ebpf_compile(unit->vm, &err_msg);
		}
		
		// init ewfd maps
		uint64_t ret_val = 0;
		res = ebpf_run_code(unit->vm, unit, sizeof(uint64_t), &ret_val);
		EBPF_VM_ERR(res);

		// load ewfd algorithm code
		ebpf_unload_code(unit->vm);
	}

	tor_assert(conf->main_code);

	res = ebpf_load(unit->vm, conf->main_code->code, conf->main_code->code_len,
				&err_msg);
	EBPF_VM_ERR(res);

	if (conf->use_jit) {
		ebpf_compile(unit->vm, &err_msg);
	}

	return unit;
}

void free_ewfd_unit(ewfd_unit_st *ewfd_unit) { 
	ewfd_unit_clear(ewfd_unit);
}

uint64_t run_ewfd_unit(ewfd_unit_st *ewfd_unit, void *ewfd_ctx, size_t len) {
	uint64_t ret_val = 0;
	int res = ebpf_run_code(ewfd_unit->vm, ewfd_ctx, len, &ret_val);
	if (res != 0) {
		EWFD_LOG("[ewfd-unit] Error: ebpf_exec failed %d", res);
		return 0;
	}
	return ret_val;
}

static void add_ewfd_tor_helpers(struct ebpf_vm *vm) {
	ebpf_register(vm, helper_ebpf_helper_log_print_id, "ebpf_log_print",  helper_ebpf_log_print);
	ebpf_register(vm, helper_test_ewfd_add_dummy_packet_id, "ewfd_add_dummy_packet", helper_ewfd_add_dummy_packet);
}

static uint64_t helper_ewfd_add_dummy_packet(uint64_t ptr, uint64_t tick) {
	return ewfd_add_dummy_packet((uintptr_t) ptr, (uint32_t) tick);
}


static uint64_t helper_ebpf_log_print(const char *fmt, uint32_t fmt_size, ...) {
	char my_log[128] = {0};
	
	va_list args;
	va_start(args, fmt);
	vsprintf(my_log, fmt, args);
	va_end(args);

	EWFD_LOG("[ebpf] %s", my_log);
	
	return 0;
}