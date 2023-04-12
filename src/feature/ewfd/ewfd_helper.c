
#include "feature/ewfd/ewfd_helper.h"
#include "feature/ewfd/circuit_padding.h"

extern int ewfd_add_dummy_packet(uintptr_t on_circ, uint32_t insert_ti);

// send a dummy packet
int send_dummy_cell(void *ewfd_status, uint32_t delay) {
	ewfd_circ_status_st *status = (ewfd_circ_status_st *) ewfd_status;
	return ewfd_add_dummy_packet(status->on_circ, delay);
}