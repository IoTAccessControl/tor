#include "../headers/ewfd.h"

#define HISTGRAM_IDX 0

SEC("ewfd/wpf-pad/padding/init")
uint64_t ewfd_init(void *ewfd_unit) {
	ewfd_histogram_init((uint64_t ) ewfd_unit, HISTGRAM_IDX, sizeof(uint8_t), sizeof(uint32_t), 16);
	return 0;
}

SEC("ewfd/wpf-pad/padding/tick")
uint64_t ewfd_tick(struct ewfd_circ_status_t *ewfd_status) {
	uint32_t tokens = ewfd_histogram_get((uint64_t) ewfd_status->ewfd_unit, HISTGRAM_IDX, 1);
	ewfd_histogram_set((uint64_t) ewfd_status->ewfd_unit, HISTGRAM_IDX, 1, tokens + 1);
	return 0;
}