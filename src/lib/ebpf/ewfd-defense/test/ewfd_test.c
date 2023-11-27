#include "ewfd_test.h"
#include "../../libebpf.h"
#include "../../ebpf_vm.h"
#include "front_code.h"
#include "wpfpad_code.h"
#include "ewfd_api.h"
#include "ewfd_helper.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>


char *err_msg;
bool use_jit = true;

int ewfd_init_front_unit(struct ewfd_unit_t *unit, void *status, size_t status_len) {
	printf("ewfd run init units----------------\n");
	struct ebpf_vm *vm = unit->vm;
	// regiser helpers
	ewfd_register_tor_test_helpers(vm);

	int res = ebpf_load(vm, ewfd_front_padding_init, sizeof(ewfd_front_padding_init) - 1, &err_msg);
	if (res != 0) {
		printf("res: %d error: %s li: %d\n", res, err_msg, __LINE__);
	}
	if (use_jit) {
		ebpf_compile(vm, &err_msg);
	}
	// assert(res == 0);

	uint64_t ret_val = 0;
	res = ebpf_run_code(vm, unit, status_len, &ret_val);
	assert(res == 0);

	// remove init code
	ebpf_unload_code(vm);

	res = ebpf_load(vm, ewfd_front_padding_tick, sizeof(ewfd_front_padding_tick) - 1, &err_msg);
	if (res != 0) {
		printf("res: %d error: %s li: %d\n", res, err_msg, __LINE__);
	}
	if (use_jit) {
		ebpf_compile(vm, &err_msg);
	}

	return res;
}

int ewfd_run_front_unit(struct ewfd_unit_t *ctx, void *status, size_t status_len) {
	printf("ewfd run tick units----------------\n");
	struct ebpf_vm *vm = ctx->vm;

	uint64_t ret_val = 0;
	int res = ebpf_run_code(vm, status, status_len, &ret_val);
	assert(res == 0);


	int op = (int)(ret_val >> 32);
	int arg = (int)(ret_val & 0xffffffff);

	printf("ret_val: %ld op: %d arg: %d\n", ret_val, op, arg);
	return res;
}

int ewfd_init_wpfpad_unit(struct ewfd_unit_t *unit, void *status, size_t status_len) {
	printf("ewfd run init units----------------\n");
	struct ebpf_vm *vm = unit->vm;
	// regiser helpers
	ewfd_register_tor_test_helpers(vm);

	int res = ebpf_load(vm, ewfd_wpf_pad_padding_init, sizeof(ewfd_wpf_pad_padding_init) - 1, &err_msg);
	if (res != 0) {
		printf("res: %d error: %s li: %d\n", res, err_msg, __LINE__);
	}
	if (use_jit) {
		ebpf_compile(vm, &err_msg);
	}
	// assert(res == 0);

	uint64_t ret_val = 0;
	res = ebpf_run_code(vm, unit, status_len, &ret_val);
	assert(res == 0);

	// remove init code
	ebpf_unload_code(vm);

	res = ebpf_load(vm, ewfd_wpf_pad_padding_tick, sizeof(ewfd_wpf_pad_padding_tick) - 1, &err_msg);
	if (res != 0) {
		printf("res: %d error: %s li: %d\n", res, err_msg, __LINE__);
	}
	if (use_jit) {
		ebpf_compile(vm, &err_msg);
	}

	return res;
}

int ewfd_run_wpfpad_unit(struct ewfd_unit_t *ctx, void *status, size_t status_len) {
	printf("ewfd run tick units----------------\n");
	struct ebpf_vm *vm = ctx->vm;

	uint64_t ret_val = 0;
	int res = ebpf_run_code(vm, status, status_len, &ret_val);
	assert(res == 0);


	int op = (int)(ret_val >> 32);
	int arg = (int)(ret_val & 0xffffffff);

	printf("ret_val: %ld op: %d arg: %d\n", ret_val, op, arg);
	return res;
}