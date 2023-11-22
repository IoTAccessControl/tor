#ifndef _EWFD_MAPS_H_
#define _EWFD_MAPS_H_

#include <stdint.h>

/*
ewfd maps:
- histogram array map
- datastream ringbuffer
*/

enum ewfd_map_type {
	EWFD_MAP_HASHMAP,
	EWFD_MAP_RINGBUFFER,
};

// typedef struct ewfd_map_op_t {
// 	// int (*map_create)();
// 	int (*map_clear)(void *ctx, uint32_t map_fd);
// } ewfd_map_op_st;

typedef struct ewfd_map_t {
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	// struct ewfd_map_op_t *map_op;
	enum ewfd_map_type map_type;
	char name[16];
} ewfd_map_st;

// https://elixir.bootlin.com/linux/v4.9/source/kernel/bpf/helpers.c#L45
typedef struct ewfd_map_fdtable_t {
	uint32_t max_fds;
	ewfd_map_st **fd_table;
} ewfd_map_fdtable_st;


struct ewfd_unit_t;

// map operations
ewfd_map_st* ewfd_map_create(struct ewfd_unit_t *unit, uint32_t map_idx, enum ewfd_map_type map_type);
ewfd_map_st* ewfd_map_get(struct ewfd_unit_t *unit, uint32_t map_idx);
void ewfd_map_free(ewfd_map_st *map);

// ringbuffer based data stream operations
int ebpf_data_stream_init(struct ewfd_unit_t *unit, uint32_t map_idx, const char *data_stream_file);
int ewfd_data_stream_load_more(struct ewfd_unit_t *unit, uint32_t data_stream_fd);
uint32_t ewfd_data_stream_fetch(struct ewfd_unit_t *unit, uint32_t data_stream_fd);
int ewfd_data_stream_dequeue(struct ewfd_unit_t *unit, uint32_t data_stream_fd);

// hashmap based histogram operations
void ewfd_histogram_init(struct ewfd_unit_t *unit, uint32_t map_idx, uint32_t key_sz, uint32_t val_sz, uint32_t max_entries);
uint32_t ewfd_histogram_get(struct ewfd_unit_t *unit, uint32_t map_idx, uint8_t index);
int ewfd_histogram_set(struct ewfd_unit_t *unit, uint32_t map_idx, uint8_t index, uint32_t token);

#endif // _EWFD_MAPS_H_
