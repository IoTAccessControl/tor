
#include "feature/ewfd/ewfd_unit.h"
#include "core/or/or.h"
#include "feature/ewfd/circuit_padding.h"
#include "feature/ewfd/debug.h"
#include "feature/ewfd/ewfd_helper.h"
#include "lib/ebpf/ebpf_vm.h"
#include "lib/ebpf/libebpf.h"
#include <stdint.h>

// extern int ebpf_exec(const struct ebpf_vm* vm, void* mem, size_t mem_len,
// uint64_t* bpf_return_value);

ewfd_unit_st *init_ewfd_unit(struct ewfd_padding_conf_t *conf) {
	ewfd_unit_st *unit = (ewfd_unit_st *)tor_malloc_zero(sizeof(ewfd_unit_st));

	// step-1: running init scripts to set the context
	unit->ebpf_vm = ebpf_create();
	char err_msg[32];
	ebpf_load(unit->ebpf_vm, conf->init_code->code, conf->init_code->code_len,
				&err_msg);

	// int res = ebpf_exec(unit->ebpf_vm, void *mem, int mem_len, uint64_t
	// *bpf_return_value);

	// step-2: setup the eBPF code

	return unit;
}

void free_ewfd_unit(ewfd_unit_st *ewfd_unit) { tor_free(ewfd_unit); }

uint64_t run_ewfd_unit(ewfd_unit_st *ewfd_unit, void *ewfd_ctx, int len) {
	uint64_t ret = 0;
	struct ebpf_vm *vm = (struct ebpf_vm *)ewfd_unit->ebpf_vm;
	if (vm->jitted) {
		return vm->jitted(ewfd_ctx, len);
	}
	int res = ebpf_exec(vm, ewfd_ctx, len, &ret);
	if (res != 0) {
		EWFD_LOG("[ewfd-unit] Error: ebpf_exec failed %d", res);
		return 0;
	}
	return ret;
}