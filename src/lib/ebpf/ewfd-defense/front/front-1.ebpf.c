#include "../headers/ewfd.h"
#include <stdint.h>



uint64_t bpf_main(struct ewfd_circ_status_t *ctx) {

	return ctx->send_cell_cnt + ctx->recv_cell_cnt;
}