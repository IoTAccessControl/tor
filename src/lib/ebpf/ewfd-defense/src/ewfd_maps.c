#include "ewfd_maps.h"

#include "ewfd_api.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "hashmap.h"

#define MAX_DATA_STREAM_SIZE 256

// hash map
// ring buffer
typedef struct ewfd_array_map_t {
	struct ewfd_map_t map;
	uint32_t *buffer;
} ewfd_array_map_st;

typedef struct ewfd_ringbuffer_t {
	struct ewfd_map_t map;
	uint32_t *buffer;
	int head;
	int tail;
	int max_size;
	int size;
} ewfd_ringbuffer_st;

typedef struct ewfd_hashmap_t {
	struct ewfd_map_t map;
	struct hashmap *hashmap;
} ewfd_hashmap_st;

static void _ewfd_data_stream_enqueue(ewfd_ringbuffer_st *rbuf, uint32_t data);

ewfd_map_st* ewfd_map_create(struct ewfd_unit_t *unit, uint32_t map_idx, enum ewfd_map_type map_type) {
	// printf("ebpf_data_stream_init: %p \n", unit);
	if (unit->map_table.fd_table == NULL) {
		unit->map_table.max_fds = 4;
		unit->map_table.fd_table = (ewfd_map_st **) calloc(1, sizeof(ewfd_map_st *) * unit->map_table.max_fds);
	}
	if (unit->map_table.max_fds <= map_idx) {
		unit->map_table.max_fds *= 2;
		unit->map_table.fd_table = (ewfd_map_st **) realloc(unit->map_table.fd_table, sizeof(ewfd_map_st *) * unit->map_table.max_fds);
	}

	if (map_type == EWFD_MAP_RINGBUFFER) {
		unit->map_table.fd_table[map_idx] = (ewfd_map_st *) calloc(1, sizeof(ewfd_ringbuffer_st));
		unit->map_table.fd_table[map_idx]->map_type = EWFD_MAP_RINGBUFFER;
	} else if (map_type == EWFD_MAP_HASHMAP) {
		ewfd_hashmap_st *map = (ewfd_hashmap_st *) calloc(1, sizeof(ewfd_hashmap_st));
		map->hashmap = NULL;
		unit->map_table.fd_table[map_idx] = (ewfd_map_st *) map;
		unit->map_table.fd_table[map_idx]->map_type = EWFD_MAP_HASHMAP;
	}

	return unit->map_table.fd_table[map_idx];
}


ewfd_map_st* ewfd_map_get(struct ewfd_unit_t *unit, uint32_t map_idx) {
	if (unit->map_table.fd_table != NULL && unit->map_table.fd_table[map_idx] != NULL) {
		return unit->map_table.fd_table[map_idx];
	}
	return NULL;
}

void ewfd_map_free(ewfd_map_st *map) {
	if (map == NULL) {
		return;
	}
	if (map->map_type == EWFD_MAP_RINGBUFFER) {
		ewfd_ringbuffer_st *rbuf = (ewfd_ringbuffer_st *) map;
		free(rbuf->buffer);
	} else if (map->map_type == EWFD_MAP_HASHMAP) {
		ewfd_hashmap_st *hmap = (ewfd_hashmap_st *) map;
		hashmap_free(hmap->hashmap);
	}
	free(map);
	// printf("%d -> free map %p\n", __LINE__, map);
}


static int load_data_by_tag(const char *tag, int **arr, int len) {
	
	return 0;
}


static int front_data_stream[] = {
	31, 93, 140, 180, 182, 206, 235, 236, 273, 296, 316, 321, 338, 349, 359, 391, 397, 412, 431, 439, 
	454, 474, 477, 496, 502, 514, 521, 536, 542, 549, 557, 565, 566, 579, 585, 586, 592, 597, 605, 607, 
	609, 620, 620, 640, 642, 643, 645, 653, 671, 696, 702, 703, 704, 710, 712, 716, 732, 737, 747, 752, 
	761, 788, 789, 803, 819, 829, 835, 837, 842, 863, 867, 870, 872, 879, 894, 902, 918, 942, 951, 956, 
	966, 976, 986, 1000, 1003, 1004, 1006, 1035, 1046, 1054, 1056, 1056, 1064, 1066, 1074, 1078, 1083, 1098, 1101, 1109, 
	1110, 1118, 1131, 1132, 1152, 1155, 1189, 1199, 1209, 1210, 1222, 1226, 1232, 1236, 1247, 1250, 1269, 1271, 1289, 1290, 
	1296, 1308, 1311, 1318, 1335, 1386, 1386, 1406, 1410, 1430, 1463, 1469, 1473, 1492, 1494, 1499, 1499, 1525, 1554, 1555, 
	1561, 1565, 1566, 1566, 1572, 1575, 1575, 1583, 1606, 1628, 1633, 1636, 1656, 1660, 1678, 1679, 1689, 1694, 1713, 1714, 
	1749, 1763, 1770, 1792, 1813, 1816, 1818, 1822, 1825, 1835, 1901, 1903, 1909, 1924, 1937, 1942, 1963, 1973, 1982, 2050, 
	2080, 2113, 2141, 2152, 2176, 2180, 2242, 2323, 2385, 2425, 2513, 2519, 2547, 2602, 2615, 2662, 2919, 3097, 3180, 3654,
};

/*
Get data from ring buffer
https://elixir.bootlin.com/linux/latest/source/kernel/bpf/arraymap.c#L82
https://github.com/CBackyx/eBPF-map/blob/master/hash_tab.c#L13
https://github.com/CBackyx/eBPF-map/blob/master/hash_tab.c#L580
*/
int ebpf_data_stream_init(struct ewfd_unit_t *unit, uint32_t map_idx, const char *data_stream_file) {
	int *arr;
	int len = 0;
	// struct ewfd_unit_t *unit = (struct ewfd_unit_t *) ctx;
	ewfd_ringbuffer_st *rb = (ewfd_ringbuffer_st *) ewfd_map_get(unit, map_idx);
	if (rb == NULL) {
		rb = (ewfd_ringbuffer_st *) ewfd_map_create(unit, map_idx, EWFD_MAP_RINGBUFFER);
	}
	int max_size = MAX_DATA_STREAM_SIZE;

	rb->buffer = (uint32_t *) malloc(max_size * sizeof(uint32_t));
	rb->head = 0;
	rb->tail = 0;
	rb->max_size = max_size;
	rb->size = 0;

	int data_stream_fd = 1;
	int pkt = ewfd_data_stream_load_more(unit, data_stream_fd);
	// printf("%d -> pkt load: %d\n", __LINE__, pkt);
	return 0;
}

static inline int _ewfd_data_stream_is_empty(ewfd_ringbuffer_st *rb) {
	return rb->size == 0;
}

static inline int _ewfd_data_stream_is_full(ewfd_ringbuffer_st *rb) {
	return (rb->size == rb->max_size);
}

static void _ewfd_data_stream_enqueue(ewfd_ringbuffer_st *rb, uint32_t data) {
	if (_ewfd_data_stream_is_full(rb)) {
		return;
	}
	rb->buffer[rb->head] = data;
	rb->head = (rb->head + 1) % rb->max_size;
	rb->size++;
}

int ewfd_data_stream_load_more(struct ewfd_unit_t *unit, uint32_t data_stream_fd) {
	ewfd_ringbuffer_st *rbuf = (ewfd_ringbuffer_st *) ewfd_map_get(unit, data_stream_fd);
	if (rbuf == NULL) {
		return -1;
	}

	int pkt = 5;
	pkt = sizeof(front_data_stream) / sizeof(int);
	for(int i = 0; i < pkt; i++) {
		_ewfd_data_stream_enqueue(rbuf, front_data_stream[i]);
	}
	return pkt;
}

uint32_t ewfd_data_stream_fetch(struct ewfd_unit_t *unit, uint32_t data_stream_fd) {
	ewfd_ringbuffer_st *rb = (ewfd_ringbuffer_st *) ewfd_map_get(unit, data_stream_fd);
	if (rb->size == 0) {
		return -1;
	}
	uint32_t data = rb->buffer[rb->tail];
	return data;
}

int ewfd_data_stream_dequeue(struct ewfd_unit_t *unit, uint32_t data_stream_fd) {
	ewfd_ringbuffer_st *rb = (ewfd_ringbuffer_st *) ewfd_map_get(unit, data_stream_fd);
	if (rb->size == 0) {
		return -1;
	}
	uint32_t data = rb->buffer[rb->tail];
	rb->tail = (rb->tail + 1) % rb->max_size;
	rb->size--;
	return data;
}


// --------------------------------------------
// eBPF hash map
// https://github.com/tidwall/hashmap.c/tree/master
// --------------------------------------------
struct hist_item_t {
	uint8_t key;
	uint32_t val;
} hist_item_st __attribute__((packed));

void ewfd_histogram_init(struct ewfd_unit_t *unit, uint32_t map_idx, uint32_t key_sz, uint32_t val_sz, uint32_t max_entries) {
	ewfd_hashmap_st *map = (ewfd_hashmap_st *) ewfd_map_get(unit, map_idx);
	if (map == NULL) {
		map = (ewfd_hashmap_st *) ewfd_map_create(unit, map_idx, EWFD_MAP_HASHMAP);
	}
	if (map->hashmap == NULL) {
		map->hashmap = hashmap_new(key_sz, key_sz + val_sz, max_entries, 0, 0, hashmap_xxhash3, hashmap_default_compare, NULL, NULL);
	}
}

uint32_t ewfd_histogram_get(struct ewfd_unit_t *unit, uint32_t map_idx, uint8_t index) {
	ewfd_hashmap_st *map = (ewfd_hashmap_st *) ewfd_map_get(unit, map_idx);
	if (map == NULL) {
		return 0;
	}
	hist_item_st *item = (hist_item_st *) hashmap_get(map->hashmap, &index);
	return item == NULL ? 0 : item->val;
}

int ewfd_histogram_set(struct ewfd_unit_t *unit, uint32_t map_idx, uint8_t index, uint32_t token) {
	
}