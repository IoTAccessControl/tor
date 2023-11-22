#ifndef EWFD_MAP_TEST_H_
#define EWFD_MAP_TEST_H_

// #include "lib/ebpf/ewfd-defense/src/hashmap.h"
#include "hashmap.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
// ** The type for the things in histogram bins (aka tokens) 
typedef uint32_t circpad_hist_token_t;

// ** The type for histogram indexes (needs to be negative for errors) 
typedef int8_t circpad_hist_index_t;

// ** The type for absolute time, from monotime_absolute_usec() 
typedef uint64_t circpad_time_t;

// ** The type for timer delays, in microseconds 
typedef uint32_t circpad_delay_t;
*/

static void basic_test_ewfd_hashmap_api(void);
static void corretness_test_ewfd_hashmap_api(void);
static void prof_ewfd_hashmap_api(void);

struct hist_item {
	uint8_t index;
	uint32_t token;
} __attribute__((packed));

static uint64_t hash_int(const void *item, size_t keysz, uint64_t seed0, uint64_t seed1) {
	return hashmap_xxhash3(item, sizeof(uint8_t), seed0, seed1);
}

static int hash_cmp_int(void *a, void *b, size_t keysz, void *udata) {
	// memcmp(a, b, keysize);
	return *(uint8_t *)a - *(uint8_t *)b;
}

/*
TODO: 接口包装成ebpf这样的：
https://github.com/CBackyx/eBPF-map/blob/master/main.c

*/

static struct hashmap* ewfd_create_hashmap(size_t key_sz, size_t ele_sz, int cap) {
	struct hashmap *map = hashmap_new(key_sz, ele_sz, cap, 0, 0, hashmap_xxhash3, hashmap_default_compare, NULL, NULL);
	return map;
}

static void ewfd_hashmap_set(struct hashmap *map, void *key, void *val) {
	hashmap_set_by_kv(map, key, val);
}

static const void *ewfd_hashmap_lookup(struct hashmap *map, void *key) {
	return hashmap_get(map, key);
}

static bool ewfd_hashmap_delete(struct hashmap *map, void *key) {
	return hashmap_delete(map, key) != NULL;
}

static void efwd_free_hashmap(struct hashmap *map) {
	hashmap_free(map);
}

static void test_basic_hashmap(void) {
	basic_test_ewfd_hashmap_api();
	corretness_test_ewfd_hashmap_api();
	prof_ewfd_hashmap_api();
}

/* 测试正确性
*/
static void basic_test_ewfd_hashmap_api(void) {
	struct hashmap *map = ewfd_create_hashmap(sizeof(uint8_t), sizeof(struct hist_item), 8);
	uint8_t key = 1;
	uint32_t val = 122;
	assert(sizeof(key) + sizeof(val) == sizeof(struct hist_item));
	ewfd_hashmap_set(map, &key, &val);
	struct hist_item *it = (struct hist_item *) ewfd_hashmap_lookup(map, &key);
	printf("val: %p \n", it);

	efwd_free_hashmap(map);
}

static void corretness_test_ewfd_hashmap_api(void) {
	int map_size = 2048;
	int *val = (int *) malloc(sizeof(int) * map_size);
	struct hashmap *map = ewfd_create_hashmap(sizeof(int), sizeof(int) * 2, map_size);
	for (int i = 0; i < map_size; i++) {
		int key = i;
		val[i] = i * i;
		ewfd_hashmap_set(map, &key, &val[i]);
	}

	for (int i = 0; i < map_size; i++) {
		int key = i;
		int *it = (int *) ewfd_hashmap_lookup(map, &key);
		int v = *(it + 1);
		// printf("val: %d key: %d\n", v, key);
		assert(v == key * key);
	}

	free(val);
	efwd_free_hashmap(map);
}

#define BENCH_RUN_N(tag, N, code) {\
	printf("%-14s ", tag); \
	clock_t begin = clock(); \
	for (int i = 0; i < N; i++) { \
		(code); \
	} \
	clock_t end = clock(); \
	double elapsed_secs = (double)(end - begin) / CLOCKS_PER_SEC; \
	printf("%d ops in %.3f secs, %.0f ns/op, %.0f op/sec\n", \
		N, elapsed_secs, \
		elapsed_secs/(double)N*1e9, \
		(double)N/elapsed_secs \
	);}

static void prof_ewfd_hashmap_api(void) {
	int N = 10000;
	int map_size = 2048;
	int *val = (int *) malloc(sizeof(int) * map_size);
	struct hashmap *map = ewfd_create_hashmap(sizeof(int), sizeof(int) * 2, map_size);
	for (int i = 0; i < map_size; i++) {
		int key = i;
		val[i] = i * i;
		ewfd_hashmap_set(map, &key, &val[i]);
	}

	BENCH_RUN_N("update", N, {
		int key = i % map_size;
		int val = key + 2;
		ewfd_hashmap_set(map, &key, &val);
	});

	BENCH_RUN_N("lookup", N, {
		int key = i % map_size;
		int *it = (int *) ewfd_hashmap_lookup(map, &key);
		assert(it && *(it + 1) == key  + 2);
	});

	BENCH_RUN_N("delete", N, {
		int key = i % map_size;
		bool res = ewfd_hashmap_delete(map, &key);
		if (i < map_size) {
			assert(res);
		} else {
			assert(!res);
		}
		// printf("delete i: %d res: %d\n", i, res);
	});

	free(val);
	efwd_free_hashmap(map);
}

#endif // EWFD_MAP_TEST_H_
