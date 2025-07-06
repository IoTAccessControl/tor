/* Copyright (c) 2013-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_foreach.h"
#include "feature/ewfd/debug.h"
#include "tinytest_macros.h"
#include <stdint.h>
#include <stdio.h>
#define CIRCUITMUX_PRIVATE
#define CIRCUITMUX_EWFD_PRIVATE

#include "core/or/or.h"
#include "core/or/circuitmux.h"
// #include "core/or/circuitmux_ewma.h"
#include "core/or/circuitmux_ewfd.h"

#include "test/fakechans.h"
#include "test/fakecircs.h"
#include "test/test.h"

/*
done
*/
static void
test_cmux_ewfd_ewma_active_circuit(void *arg)
{
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;

  (void) arg;

 
}

static void
test_cmux_ewfd_ewma_xmit_cell(void *arg)
{
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;
  ewfd_policy_data_t *ewfd_pol_data;
  ewfd_policy_circ_data_t *ewfd_data;
  double old_cell_count;

  (void) arg;

}

static void *
cmux_ewfd_setup_test(const struct testcase_t *tc)
{
  static int whatever;

  (void) tc;

  EWFD_LOG("cmux_ewfd_setup_test");

  // tor_assert(-1);

  return &whatever;
}

static void
test_cmux_ewfd_ewma_notify_circ(void *arg)
{
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;
  const ewfd_policy_data_t *ewma_pol_data;

  (void) arg;

}

static void
test_cmux_ewfd_ewma_policy_circ_data(void *arg)
{
 circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t pol_data; /* garbage */
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;
  const ewfd_policy_circ_data_t *ewma_data;

  (void) arg;

  
}

static void
test_cmux_ewfd_ewma_policy_data(void *arg)
{
  circuitmux_t cmux; /* garbage. */
  circuitmux_policy_data_t *pol_data = NULL;
  const ewfd_policy_data_t *ewma_pol_data;

  (void) arg;

  
}

/** heap_test：默认min-heap
 */
struct heap_item {
  int heap_idx;
  int val;
};

static int my_heap_cmp(const void *it1, const void *it2) {
  const struct heap_item *i1 = it1, *i2 = it2;
  return i1->val - i2->val;
};

static void
test_cmux_ewfd_heap_explore(void *arg)
{
  smartlist_t *test_heap = smartlist_new();
  struct heap_item items[] = {
      {1, 11},
      {2, 22},
      {3, 33},
      {4, 44},
      {5, 55},
  };

  for (int i = 0; i < 5; i++) {
    smartlist_pqueue_add(test_heap, my_heap_cmp, offsetof(struct heap_item, heap_idx), &items[i]);
  }

  SMARTLIST_FOREACH_BEGIN(
      test_heap,
      struct heap_item*, it) {
        printf("heap_idx: %d, val: %d\n", it->heap_idx, it->val);
  } SMARTLIST_FOREACH_END(it);

  struct heap_item * it = smartlist_pqueue_pop(test_heap, my_heap_cmp, offsetof(struct heap_item, heap_idx));
  printf("pop: %d\n", it->val);
  it = smartlist_pqueue_pop(test_heap, my_heap_cmp, offsetof(struct heap_item, heap_idx));
  printf("pop: %d\n", it->val);
  it = smartlist_pqueue_pop(test_heap, my_heap_cmp, offsetof(struct heap_item, heap_idx));
  printf("pop: %d\n", it->val);
}

static void test_cmux_ewfd_delay_policy_data(void *args) {
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  const ewfd_policy_data_t *delay_policy_data;

  (void) args;

  pol_data = ewfd_delay_policy.alloc_cmux_data(&cmux);
  tt_assert(pol_data);
  tt_uint_op(pol_data->magic, OP_EQ, EWFD_POL_DATA_MAGIC);

  delay_policy_data = TO_EWFD_POL_DATA(pol_data);
  tt_assert(delay_policy_data->active_circuit_pqueue);
  // printf("active_circuit_pqueue_last_recalibrated: %d\n", delay_policy_data->active_circuit_pqueue_last_recalibrated);
  // tt_uint_op(delay_policy_data->active_circuit_pqueue_last_recalibrated, OP_NE, 0);

done:
  ewfd_delay_policy.free_cmux_data(&cmux, pol_data);
}

static void test_cmux_ewfd_delay_policy_circ_data(void *args) {
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t pol_data; /* garbage */
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;
  const ewfd_policy_circ_data_t *delay_data;

  (void) args;

  circ_data = ewfd_delay_policy.alloc_circ_data(&cmux, &pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(circ_data);
  tt_uint_op(circ_data->magic, OP_EQ, EWFD_POL_CIRC_DATA_MAGIC);

  delay_data = TO_EWFD_POL_CIRC_DATA(circ_data);
  tt_mem_op(delay_data->circ, OP_EQ, &circ, sizeof(circuit_t));
  // tt_uint_op(delay_data->cell_ewfd_delay.next_burst_ti, OP_EQ, 0);
  // tt_uint_op(delay_data->cell_ewfd_delay.remain_real_pkt, OP_EQ, 0);
  // tt_uint_op(delay_data->cell_ewfd_delay.next_send_cnt, OP_EQ, 0);
  tt_int_op(delay_data->cell_ewfd_delay.heap_index, OP_EQ, -1);

done:
  ewfd_delay_policy.free_circ_data(&cmux, &pol_data, &circ, circ_data);
}

static void test_cmux_ewfd_delay_active_circuit(void *args) {
  // 4000 cirucit, active 
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuitmux_policy_circ_data_t *pol_circ_data = NULL;
  circuit_t circ; /* garbage */

  (void) args;

  pol_data = ewfd_delay_policy.alloc_cmux_data(&cmux);
  pol_circ_data = ewfd_delay_policy.alloc_circ_data(&cmux, pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(pol_data);
  tt_assert(pol_circ_data);

  // add to queue
  ewfd_delay_policy.notify_circ_active(&cmux, pol_data, &circ, pol_circ_data);
  circuit_t *p_circ = ewfd_delay_policy.pick_active_circuit(&cmux, pol_data);
  tt_mem_op(p_circ, OP_EQ, &circ, sizeof(circuit_t));

done:
  ewfd_delay_policy.free_circ_data(&cmux, pol_data, &circ, pol_circ_data);
  ewfd_delay_policy.free_cmux_data(&cmux, pol_data);
}

static void test_cmux_ewfd_delay_notify_circ(void *args) {
  // notify_circ_active -> notify_circ_inactive
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuitmux_policy_circ_data_t *pol_circ_data = NULL;
  circuit_t circ; /* garbage */

  (void) args;

  pol_data = ewfd_delay_policy.alloc_cmux_data(&cmux);
  pol_circ_data = ewfd_delay_policy.alloc_circ_data(&cmux, pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(pol_data);
  tt_assert(pol_circ_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);

  // add to queue
  ewfd_delay_policy.notify_circ_active(&cmux, pol_data, &circ, pol_circ_data);
  tt_int_op(smartlist_len(pol->active_circuit_pqueue), OP_EQ, 1);

  // remove from queue
  ewfd_delay_policy.notify_circ_inactive(&cmux, pol_data, &circ, pol_circ_data);
  tt_int_op(smartlist_len(pol->active_circuit_pqueue), OP_EQ, 0);

done:
  ewfd_delay_policy.free_circ_data(&cmux, pol_data, &circ, pol_circ_data);
  ewfd_delay_policy.free_cmux_data(&cmux, pol_data);
}

static void test_cmux_ewfd_delay_xmit_cell(void *args) {
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuitmux_policy_circ_data_t *pol_circ_data = NULL;
  circuit_t circ; /* garbage */

  (void) args;

  pol_data = ewfd_delay_policy.alloc_cmux_data(&cmux);
  pol_circ_data = ewfd_delay_policy.alloc_circ_data(&cmux, pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(pol_data);
  tt_assert(pol_circ_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);

  ewfd_delay_policy.notify_set_n_cells(&cmux, pol_data, &circ, pol_circ_data, 10);

  // add to queue
  ewfd_delay_policy.notify_circ_active(&cmux, pol_data, &circ, pol_circ_data);
  ewfd_delay_policy.notify_xmit_cells(&cmux, pol_data, &circ, pol_circ_data, 1);

  tt_int_op(circ_data->cell_ewfd_delay.remain_real_pkt, OP_EQ, 9);

done:
  ewfd_delay_policy.free_circ_data(&cmux, pol_data, &circ, pol_circ_data);
  ewfd_delay_policy.free_cmux_data(&cmux, pol_data);
}

// delay_cmp_cell
static void test_cmux_ewfd_delay_cmp_cell(void *args) {
}

// delay_pick_many_cell
static void test_cmux_ewfd_delay_pick_many_cell(void *args) {
}

static int
cmux_ewfd_cleanup_test(const struct testcase_t *tc, void *ptr)
{
  (void) tc;
  (void) ptr;

  return 1;
}

static struct testcase_setup_t cmux_ewfd_test_setup = {
  .setup_fn = cmux_ewfd_setup_test,
  .cleanup_fn = cmux_ewfd_cleanup_test,
};

#define TEST_CMUX_EWFD(name) \
  { #name, test_cmux_ewfd_##name, TT_FORK, &cmux_ewfd_test_setup, NULL }

#define TEST_EWFD(name) \
  { #name, test_ewfd_##name, TT_FORK, &cmux_ewfd_test_setup, NULL }


/*
* customize test cases
*/
#define EWFD_UNITEST_TEST_PRIVATE
#include "feature/ewfd/ewfd.h"
#include "feature/ewfd/ebpf_api.h"
#include "core/or/origin_circuit_st.h"

/* 测试函数
ewfd_get_event_num
ewfd_remove_remain_events
*/
static void test_ewfd_event_queue_delete(void *args) {
  ewfd_framework_init();
  start_ewfd_padding_framework();
  or_circuit_t circ1, circ2, circ3;
  circ1.base_.magic = OR_CIRCUIT_MAGIC;
  circ1.base_.purpose = 0;
  circ1.p_circ_id = 1;
  circ2.base_.magic = OR_CIRCUIT_MAGIC;
  circ2.base_.purpose = 0;
  circ2.p_circ_id = 2;
  circ3.base_.magic = OR_CIRCUIT_MAGIC;
  circ3.base_.purpose = 0;
  circ3.p_circ_id = 3;

  // ewfd_get_circuit_id(&circ1);

  ewfd_add_dummy_packet((uintptr_t) &circ1, 100);
  ewfd_add_dummy_packet((uintptr_t) &circ1, 100);
  ewfd_add_dummy_packet((uintptr_t) &circ1, 100);
  ewfd_add_dummy_packet((uintptr_t) &circ2, 100);
  ewfd_add_dummy_packet((uintptr_t) &circ3, 100);

  // test queue poll 

  // printf("circ1: %p\n", &circ1);
  // printf("circ2: %p\n", &circ2);
  // printf("circ3: %p\n", &circ3);

  // test queue delete
  tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 3);
  tt_int_op(ewfd_get_event_num((uintptr_t) &circ2), OP_EQ, 1);
  tt_int_op(ewfd_get_event_num((uintptr_t) &circ3), OP_EQ, 1);

  ewfd_remove_remain_events((uintptr_t) &circ1);

  tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 0);
  tt_int_op(ewfd_get_event_num((uintptr_t) &circ2), OP_EQ, 1);
  tt_int_op(ewfd_get_event_num((uintptr_t) &circ3), OP_EQ, 1);

done:
  ewfd_framework_free();
}

// 需要手动打开 ewfd.c 中 EWFD_UNITEST_TEST_PRIVATE 宏
static void test_ewfd_event_queue_poll(void *args) {
  ewfd_framework_init();
  start_ewfd_padding_framework();

  or_circuit_t circ1, circ2, circ3;
  circ1.base_.magic = OR_CIRCUIT_MAGIC;
  circ1.base_.purpose = 0;
  circ1.p_circ_id = 1;
  circ2.base_.magic = OR_CIRCUIT_MAGIC;
  circ2.base_.purpose = 0;
  circ2.p_circ_id = 2;
  circ3.base_.magic = OR_CIRCUIT_MAGIC;
  circ3.base_.purpose = 0;
  circ3.p_circ_id = 3;

  printf("circ1: %d %p\n", ewfd_get_circuit_id((circuit_t *) &circ1), &circ1);
  printf("circ2: %d %p\n", ewfd_get_circuit_id((circuit_t *) &circ2), &circ2);
  printf("circ3: %d %p\n", ewfd_get_circuit_id((circuit_t *) &circ3), &circ3);
  
  uint64_t it1 = 100, it2 = 150, it3 = 2200, it4 = 4100;

  ewfd_op_delay((uintptr_t) &circ1, it1, 2000, 5);
  ewfd_op_delay((uintptr_t) &circ1, it2, 2000, 5);
  ewfd_op_delay((uintptr_t) &circ1, it3, 2000, 5);
  ewfd_op_delay((uintptr_t) &circ1, it4, 2000, 5);

  int tick = 0;
  while (1) {
    tick++;
    if (tick > 100) {
      break;
    }
    // MAX_EWFD_TICK_GAP_MS 50ms
    uint64_t cur_ti = tick * 50;
    on_event_queue_tick(NULL, &cur_ti);

    // 
    int delay = 50 * 2;
    printf("cur_ti: %d num: %d\n", cur_ti, ewfd_get_event_num((uintptr_t) &circ1));
    if (cur_ti < it2) {
      tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 4);
    }
    
    if (cur_ti == it2) {
      tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 3);
    }

    if (cur_ti > 500 && cur_ti < it3) {
      tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 2);
    }

    if (cur_ti == it3 + delay) {
      tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 1);
    }

    if (cur_ti >= it4 + delay) {
      tt_int_op(ewfd_get_event_num((uintptr_t) &circ1), OP_EQ, 0);
    }
  }
done:
  ewfd_framework_free();
}

struct testcase_t circuitmux_ewfd_tests[] = {
  TEST_CMUX_EWFD(ewma_active_circuit), // checked
  TEST_CMUX_EWFD(ewma_policy_data),
  TEST_CMUX_EWFD(ewma_policy_circ_data),
  TEST_CMUX_EWFD(ewma_notify_circ),
  TEST_CMUX_EWFD(ewma_xmit_cell),
  TEST_CMUX_EWFD(heap_explore),
  TEST_CMUX_EWFD(delay_policy_data),
  TEST_CMUX_EWFD(delay_policy_circ_data),
  TEST_CMUX_EWFD(delay_active_circuit),
  TEST_CMUX_EWFD(delay_notify_circ),
  TEST_CMUX_EWFD(delay_xmit_cell),
  TEST_CMUX_EWFD(delay_cmp_cell),
  TEST_CMUX_EWFD(delay_pick_many_cell),
  // customize test cases
  TEST_EWFD(event_queue_delete),
  TEST_EWFD(event_queue_poll),
  END_OF_TESTCASES
};
