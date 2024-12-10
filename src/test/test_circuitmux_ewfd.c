/* Copyright (c) 2013-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_foreach.h"
#include "feature/ewfd/debug.h"
#include "tinytest_macros.h"
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

  pol_data = ewfd_ewma_policy.alloc_cmux_data(&cmux);
  tt_assert(pol_data);

  circ_data = ewfd_ewma_policy.alloc_circ_data(&cmux, pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(circ_data);

  /* Get EWMA specific objects. */

  /* Make circuit active. */
  ewfd_ewma_policy.notify_circ_active(&cmux, pol_data, &circ, circ_data);

  circuit_t *entry = ewfd_ewma_policy.pick_active_circuit(&cmux, pol_data);
  tt_mem_op(entry, OP_EQ, &circ, sizeof(circ));

 done:
  ewfd_ewma_policy.free_circ_data(&cmux, pol_data, &circ, circ_data);
  ewfd_ewma_policy.free_cmux_data(&cmux, pol_data);
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

  pol_data = ewfd_ewma_policy.alloc_cmux_data(&cmux);
  tt_assert(pol_data);
  circ_data = ewfd_ewma_policy.alloc_circ_data(&cmux, pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(circ_data);
  ewfd_pol_data = TO_EWFD_POL_DATA(pol_data);
  ewfd_data = TO_EWFD_POL_CIRC_DATA(circ_data);

  /* Make circuit active. */
  ewfd_ewma_policy.notify_circ_active(&cmux, pol_data, &circ, circ_data);

  /* Move back in time the last time we calibrated so we scale the active
   * circuit when emitting a cell. */
  ewfd_pol_data->active_circuit_pqueue_last_recalibrated -= 100;
  ewfd_data->cell_ewfd_ewma.last_adjusted_tick =
    ewfd_pol_data->active_circuit_pqueue_last_recalibrated;

  /* Grab old cell count. */
  old_cell_count = ewfd_data->cell_ewfd_ewma.cell_count;

  ewfd_ewma_policy.notify_xmit_cells(&cmux, pol_data, &circ, circ_data, 1);

  /* Our old cell count should be lower to what we have since we just emitted
   * a cell and thus we scale. */
  tt_double_op(old_cell_count, OP_LT, ewfd_data->cell_ewfd_ewma.cell_count);

 done:
  ewfd_ewma_policy.free_circ_data(&cmux, pol_data, &circ, circ_data);
  ewfd_ewma_policy.free_cmux_data(&cmux, pol_data);
}

static void *
cmux_ewfd_setup_test(const struct testcase_t *tc)
{
  static int whatever;

  (void) tc;

  EWFD_LOG("cmux_ewfd_setup_test");

//   cell_ewma_initialize_ticks();
	cell_ewfd_ewma_initialize_ticks();
  // cmux_ewma_set_options(NULL, NULL);
  tor_assert(-1);

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

  pol_data = ewfd_ewma_policy.alloc_cmux_data(&cmux);
  tt_assert(pol_data);
  circ_data = ewfd_ewma_policy.alloc_circ_data(&cmux, pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(circ_data);

  /* Currently, notify_circ_active() ignores cmux and circ. They can not be
   * NULL so it is fine to pass garbage. */
  ewfd_ewma_policy.notify_circ_active(&cmux, pol_data, &circ, circ_data);

  /* We should have an active circuit in the queue so its EWMA value can be
   * tracked. */
  ewma_pol_data = TO_EWFD_POL_DATA(pol_data);
  tt_int_op(smartlist_len(ewma_pol_data->active_circuit_pqueue), OP_EQ, 1);
  tt_uint_op(ewma_pol_data->active_circuit_pqueue_last_recalibrated, OP_NE, 0);

  ewfd_ewma_policy.notify_circ_inactive(&cmux, pol_data, &circ, circ_data);
  /* Should be removed from the active queue. */
  ewma_pol_data = TO_EWFD_POL_DATA(pol_data);
  tt_int_op(smartlist_len(ewma_pol_data->active_circuit_pqueue), OP_EQ, 0);
  tt_uint_op(ewma_pol_data->active_circuit_pqueue_last_recalibrated, OP_NE, 0);

 done:
  ewfd_ewma_policy.free_circ_data(&cmux, pol_data, &circ, circ_data);
  ewfd_ewma_policy.free_cmux_data(&cmux, pol_data);
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

  /* Currently, alloc_circ_data() ignores every parameter _except_ the cell
   * direction so it is OK to pass garbage. They can not be NULL. */
  circ_data = ewfd_ewma_policy.alloc_circ_data(&cmux, &pol_data, &circ,
                                          CELL_DIRECTION_OUT, 42);
  tt_assert(circ_data);
  tt_uint_op(circ_data->magic, OP_EQ, EWFD_POL_CIRC_DATA_MAGIC);

  ewma_data = TO_EWFD_POL_CIRC_DATA(circ_data);
  tt_mem_op(ewma_data->circ, OP_EQ, &circ, sizeof(circuit_t));
  tt_double_op(ewma_data->cell_ewfd_ewma.cell_count, OP_LE, 0.0);
  tt_int_op(ewma_data->cell_ewfd_ewma.heap_index, OP_EQ, -1);
  tt_uint_op(ewma_data->cell_ewfd_ewma.is_for_p_chan, OP_EQ, 0);
  ewfd_ewma_policy.free_circ_data(&cmux, &pol_data, &circ, circ_data);

  circ_data = ewfd_ewma_policy.alloc_circ_data(&cmux, &pol_data, &circ,
                                          CELL_DIRECTION_IN, 42);
  tt_assert(circ_data);
  tt_uint_op(circ_data->magic, OP_EQ, EWFD_POL_CIRC_DATA_MAGIC);

  ewma_data = TO_EWFD_POL_CIRC_DATA(circ_data);
  tt_mem_op(ewma_data->circ, OP_EQ, &circ, sizeof(circuit_t));
  tt_double_op(ewma_data->cell_ewfd_ewma.cell_count, OP_LE, 0.0);
  tt_int_op(ewma_data->cell_ewfd_ewma.heap_index, OP_EQ, -1);
  tt_uint_op(ewma_data->cell_ewfd_ewma.is_for_p_chan, OP_EQ, 1);

 done:
  ewfd_ewma_policy.free_circ_data(&cmux, &pol_data, &circ, circ_data);
}

static void
test_cmux_ewfd_ewma_policy_data(void *arg)
{
  circuitmux_t cmux; /* garbage. */
  circuitmux_policy_data_t *pol_data = NULL;
  const ewfd_policy_data_t *ewma_pol_data;

  (void) arg;

  pol_data = ewfd_ewma_policy.alloc_cmux_data(&cmux);
  tt_assert(pol_data);
  tt_uint_op(pol_data->magic, OP_EQ, EWFD_POL_DATA_MAGIC);

  /* Test EWMA object. */
  ewma_pol_data = TO_EWFD_POL_DATA(pol_data);
  tt_assert(ewma_pol_data->active_circuit_pqueue);
  tt_uint_op(ewma_pol_data->active_circuit_pqueue_last_recalibrated, OP_NE, 0);

 done:
  ewfd_ewma_policy.free_cmux_data(&cmux, pol_data);
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
  tt_uint_op(delay_data->cell_ewfd_delay.next_send_tick, OP_EQ, 0);
  tt_uint_op(delay_data->cell_ewfd_delay.all_real_pkt, OP_EQ, 0);
  tt_uint_op(delay_data->cell_ewfd_delay.next_send_cnt, OP_EQ, 0);
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

  tt_int_op(circ_data->cell_ewfd_delay.all_real_pkt, OP_EQ, 9);

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

  circuitmux_ewfd_free_all();
  return 1;
}

static struct testcase_setup_t cmux_ewfd_test_setup = {
  .setup_fn = cmux_ewfd_setup_test,
  .cleanup_fn = cmux_ewfd_cleanup_test,
};

#define TEST_CMUX_EWFD(name) \
  { #name, test_cmux_ewfd_##name, TT_FORK, &cmux_ewfd_test_setup, NULL }

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

  END_OF_TESTCASES
};
