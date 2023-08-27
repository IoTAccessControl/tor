#include "ewfd_helper.h"
#include "../../libebpf.h"
#include "../../ebpf_vm.h"
#include "ewfd_api.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


/*
* ewfd helpers 
*/
static long helper_ebpf_helper_log_print_id = 1;

// helper for efwd
static long helper_test_ewfd_add_dummy_packet_id = 6;

// helper for data stream
static long helper_ebpf_data_stream_init_id = 11;
static long helper_ewfd_data_stream_load_more_id = 12;
static long helper_ewfd_data_stream_fetch_id = 13;
static long helper_ewfd_data_stream_dequeue_id = 14;

// helper for histogram
static long ebpf_init_histogram_id = 21;


static int test_ewfd_add_dummy_packet(void *ctx, uint32_t start_ti) {
	printf("[DROP] at %u\n", start_ti);
}

static long ebpf_log_print(const char *fmt, uint32_t fmt_size, ...) {
	va_list args;
	va_start(args, fmt_size);
	long ret = vprintf(fmt, args);
	va_end(args);
	return 0;
}

void ewfd_register_datastream_helpers(struct ebpf_vm *vm) {
	ebpf_register(vm, helper_ebpf_data_stream_init_id, "ebpf_data_stream_init", ebpf_data_stream_init);
	ebpf_register(vm, helper_ewfd_data_stream_load_more_id, "ewfd_data_stream_load_more", ewfd_data_stream_load_more);
	ebpf_register(vm, helper_ewfd_data_stream_fetch_id, "ewfd_data_stream_fetch", ewfd_data_stream_fetch);
	ebpf_register(vm, helper_ewfd_data_stream_dequeue_id, "ewfd_data_stream_dequeue", ewfd_data_stream_dequeue);
}

void ewfd_register_histrogram_helpers(struct ebpf_vm *vm) {
	// ebpf_register(vm, ebpf_init_histogram_id, "ebpf_init_histogram", ebpf_init_histogram);
}

void ewfd_register_tor_test_helpers(struct ebpf_vm *vm) {
	ebpf_register(vm, helper_ebpf_helper_log_print_id, "ebpf_log_print", ebpf_log_print);
	ebpf_register(vm, helper_test_ewfd_add_dummy_packet_id, "test_ewfd_add_dummy_packet", test_ewfd_add_dummy_packet);
}