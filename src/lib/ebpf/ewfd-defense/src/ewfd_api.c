#include "ewfd_api.h"
#include "../../libebpf.h"
#include "../../ebpf_vm.h"
#include "ewfd_helper.h"

#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct ewfd_unit_t *ewfd_unit_new(void) {
	struct ewfd_unit_t * unit = (struct ewfd_unit_t *) calloc(1, sizeof(struct ewfd_unit_t));
	unit->vm = ebpf_create();
	ewfd_register_datastream_helpers(unit->vm);
	ewfd_register_histrogram_helpers(unit->vm);
	
	return unit;
}

void ewfd_unit_clear(struct ewfd_unit_t *ctx) {
	// printf("ewfd clear units----------------\n");
	// clear maps
	if (ctx->map_table.fd_table != NULL) {
		for (uint32_t i = 0; i < ctx->map_table.max_fds; i++) {
			if (ctx->map_table.fd_table[i] != NULL) {
				// if (ctx->map_table.fd_table[i]->map_op != NULL) {
				// 	ctx->map_table.fd_table[i]->map_op->map_clear(ctx, i);
				// }
				ewfd_map_free(ctx->map_table.fd_table[i]);
			}
			// printf("free map: %d %p\n", i, ctx->map_table.fd_table[i]);
		}
		free(ctx->map_table.fd_table);
	}
	if (ctx->vm != NULL) {
		ebpf_destroy(ctx->vm);
	}
	free(ctx);
}


int ebpf_run_code(struct ebpf_vm *vm, void *mem, size_t mem_len, uint64_t *ret_val) {
	if (vm->jitted) {
		// printf("run jit code: %d\n", __LINE__);
		*ret_val = vm->jitted(mem, mem_len);
		return 0;
	}
	return ebpf_exec(vm, mem, mem_len, ret_val);
}