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

static void test_map_api(void) {
	basic_test_ewfd_hashmap_api();
	// printf("hashmap run: %d\n", sizeof(struct hist_item));
	// int seed = time(NULL);
	// struct hashmap *map = hashmap_new(sizeof(uint8_t), sizeof(struct hist_item), 8, seed, seed, hashmap_xxhash3, hash_cmp_int, NULL, NULL);
	// struct hist_item it = { .index = 1, .token = 15 };
	// hashmap_set(map, &it);
	// uint8_t key = 1;
	// struct hist_item *it2 = (struct hist_item *) hashmap_get(map, &key);
	// printf("val: %d\n", it2->token);
	// hashmap_free(map);
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
	
}

static void prof_ewfd_hashmap_api(void) {

}

#endif // EWFD_MAP_TEST_H_
