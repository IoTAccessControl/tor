/* Copyright (c) 2013-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITMUX_PRIVATE
#define CIRCUITMUX_EWFD_PRIVATE

#include "core/or/or.h"
#include "core/or/circuitmux.h"
// #include "core/or/circuitmux_ewma.h"
#include "core/or/circuitmux_ewfd.h"

#include "test/fakechans.h"
#include "test/fakecircs.h"
#include "test/test.h"

static void
test_cmux_ewfd_active_circuit(void *arg)
{
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;

  (void) arg;

//   pol_data = ewma_policy.alloc_cmux_data(&cmux);
//   tt_assert(pol_data);
//   circ_data = ewma_policy.alloc_circ_data(&cmux, pol_data, &circ,
//                                           CELL_DIRECTION_OUT, 42);
//   tt_assert(circ_data);

//   /* Get EWMA specific objects. */

//   /* Make circuit active. */
//   ewma_policy.notify_circ_active(&cmux, pol_data, &circ, circ_data);

//   circuit_t *entry = ewma_policy.pick_active_circuit(&cmux, pol_data);
//   tt_mem_op(entry, OP_EQ, &circ, sizeof(circ));

//  done:
//   ewma_policy.free_circ_data(&cmux, pol_data, &circ, circ_data);
//   ewma_policy.free_cmux_data(&cmux, pol_data);
}

static void
test_cmux_ewfd_xmit_cell(void *arg)
{
  circuitmux_t cmux; /* garbage */
  circuitmux_policy_data_t *pol_data = NULL;
  circuit_t circ; /* garbage */
  circuitmux_policy_circ_data_t *circ_data = NULL;
//   ewma_policy_data_t *ewma_pol_data;
//   ewma_policy_circ_data_t *ewma_data;
  double old_cell_count;

  (void) arg;


//  done:
//   ewma_policy.free_circ_data(&cmux, pol_data, &circ, circ_data);
//   ewma_policy.free_cmux_data(&cmux, pol_data);
}

static void *
cmux_ewfd_setup_test(const struct testcase_t *tc)
{
  static int whatever;

  (void) tc;

//   cell_ewma_initialize_ticks();
	cell_ewfd_initialize_ticks();
  // cmux_ewma_set_options(NULL, NULL);

  return &whatever;
}

static int
cmux_ewfd_cleanup_test(const struct testcase_t *tc, void *ptr)
{
  (void) tc;
  (void) ptr;

//   circuitmux_ewma_free_all();

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
  TEST_CMUX_EWFD(active_circuit),
  TEST_CMUX_EWFD(xmit_cell),

  END_OF_TESTCASES
};
