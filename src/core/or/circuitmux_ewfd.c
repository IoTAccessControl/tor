#define CIRCUITMUX_EWFD_PRIVATE

#include "circuitmux_ewfd.h"
#include "feature/ewfd/debug.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include <math.h>

/*** Static declarations for circuitmux_ewma.c ***/

#define EWMA_TICK_LEN_DEFAULT 10
#define EWMA_TICK_LEN_MIN 1
#define EWMA_TICK_LEN_MAX 600
static int ewfd_ewma_tick_len = EWMA_TICK_LEN_DEFAULT;
static double ewfd_ewma_scale_factor = 0.1;

static void add_cell_ewfd(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma);
static int compare_cell_ewfd_counts(const void *p1, const void *p2);
static circuit_t * cell_ewfd_to_circuit(cell_ewfd_ewma_t *ewfd_conf);
static inline double get_scale_factor(unsigned from_tick, unsigned to_tick);
static cell_ewfd_ewma_t * pop_first_cell_ewfd(ewfd_policy_data_t *pol);
static void remove_cell_ewfd(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma);
static void scale_single_cell_ewfd_ewma(cell_ewfd_ewma_t *ewma, unsigned cur_tick);
static void scale_active_circuits(ewfd_policy_data_t *pol,
                                  unsigned cur_tick);

/*** Circuitmux policy methods ***/

static circuitmux_policy_data_t * ewfd_alloc_cmux_data(circuitmux_t *cmux);
static void ewfd_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data);
static circuitmux_policy_circ_data_t *
ewfd_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                     circuit_t *circ, cell_direction_t direction,
                     unsigned int cell_count);
static void
ewfd_free_circ_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_notify_circ_active(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_notify_circ_inactive(circuitmux_t *cmux,
                          circuitmux_policy_data_t *pol_data,
                          circuit_t *circ,
                          circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_notify_xmit_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells);
static circuit_t *
ewfd_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data);
static int
ewfd_cmp_cmux(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
              circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2);

/*** EWFD circuitmux_policy_t method table ***/

circuitmux_policy_t ewfd_policy = {
  /*.alloc_cmux_data =*/ ewfd_alloc_cmux_data,
  /*.free_cmux_data =*/ ewfd_free_cmux_data,
  /*.alloc_circ_data =*/ ewfd_alloc_circ_data,
  /*.free_circ_data =*/ ewfd_free_circ_data,
  /*.notify_circ_active =*/ ewfd_notify_circ_active,
  /*.notify_circ_inactive =*/ ewfd_notify_circ_inactive,
  /*.notify_set_n_cells =*/ NULL, /* EWMA doesn't need this */
  /*.notify_xmit_cells =*/ ewfd_notify_xmit_cells,
  /*.pick_active_circuit =*/ ewfd_pick_active_circuit,
  /*.cmp_cmux =*/ ewfd_cmp_cmux
};


/** Have we initialized the ewma tick-counting logic? */
static int ewfd_ewma_ticks_initialized = 0;
/** At what monotime_coarse_t did the current tick begin? */
static monotime_coarse_t start_of_current_tick;
/** What is the number of the current tick? */
static unsigned current_tick_num;

// done
static circuit_t *
cell_ewfd_to_circuit(cell_ewfd_ewma_t *ewma)
{
  ewfd_policy_circ_data_t *cdata = NULL;

  tor_assert(ewma);
  cdata = SUBTYPE_P(ewma, ewfd_policy_circ_data_t, cell_ewfd_ewma);
  tor_assert(cdata);

  return cdata->circ;
}

static void add_cell_ewfd(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma)
{
  tor_assert(pol);
  tor_assert(ewma);

    scale_single_cell_ewfd_ewma(
      ewma,
      pol->active_circuit_pqueue_last_recalibrated);

  smartlist_add(pol->active_circuit_pqueue, ewma);
  ewma->heap_index = smartlist_len(pol->active_circuit_pqueue) - 1;
  EWFD_LOG("Added circuit %p", cell_ewfd_to_circuit(ewma));
}

static int compare_cell_ewfd_counts(const void *p1, const void *p2) 
{
  const cell_ewfd_ewma_t *ewma1 = p1, *ewma2 = p2;
  if (ewma1->cell_count < ewma2->cell_count)
    return -1;
  if (ewma1->cell_count > ewma2->cell_count)
    return 1;
  return 0;
}

static void remove_cell_ewfd(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma)
{
  tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);
  tor_assert(ewma);
  tor_assert(ewma->heap_index != -1);

  smartlist_pqueue_remove(pol->active_circuit_pqueue,
                          compare_cell_ewfd_counts,
                          offsetof(cell_ewfd_ewma_t, heap_index),
                          ewma);
}

static cell_ewfd_ewma_t * pop_first_cell_ewfd(ewfd_policy_data_t *pol)
{
    tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);

  return smartlist_pqueue_pop(pol->active_circuit_pqueue,
                              compare_cell_ewfd_counts,
                              offsetof(cell_ewfd_ewma_t, heap_index));
}

static inline double get_scale_factor(unsigned from_tick, unsigned to_tick)
{
  return pow(ewfd_ewma_scale_factor, to_tick - from_tick);
}

static void scale_single_cell_ewfd_ewma(cell_ewfd_ewma_t *ewma, unsigned cur_tick)
{
  double factor = get_scale_factor(ewma->last_adjusted_tick, cur_tick);
  ewma->cell_count *= factor;
  ewma->last_adjusted_tick = cur_tick;
}

/**
 * Initialize the system that tells which ewma tick we are in.
 */
STATIC void
cell_ewfd_ewma_initialize_ticks(void)
{
  if (ewfd_ewma_ticks_initialized)
    return;
  monotime_coarse_get(&start_of_current_tick);
  crypto_rand((char*)&current_tick_num, sizeof(current_tick_num));
  ewfd_ewma_ticks_initialized = 1;
}

/** Compute the current cell_ewma tick and the fraction of the tick that has
 * elapsed between the start of the tick and the current time.  Return the
 * former and store the latter in *<b>remainder_out</b>.
 *
 * These tick values are not meant to be shared between Tor instances, or used
 * for other purposes. */
STATIC unsigned
cell_ewfd_ewma_get_current_tick_and_fraction(double *remainder_out)
{
  if (BUG(!ewfd_ewma_ticks_initialized)) {
    cell_ewfd_ewma_initialize_ticks(); // LCOV_EXCL_LINE
  }
  monotime_coarse_t now;
  monotime_coarse_get(&now);
  int32_t msec_diff = monotime_coarse_diff_msec32(&start_of_current_tick,
                                                  &now);
  if (msec_diff > (1000*ewfd_ewma_tick_len)) {
    unsigned ticks_difference = msec_diff / (1000*ewfd_ewma_tick_len);
    monotime_coarse_add_msec(&start_of_current_tick,
                             &start_of_current_tick,
                             ticks_difference * 1000 * ewfd_ewma_tick_len);
    current_tick_num += ticks_difference;
    msec_diff %= 1000*ewfd_ewma_tick_len;
  }
  *remainder_out = ((double)msec_diff) / (1.0e3 * ewfd_ewma_tick_len);
  return current_tick_num;
}


/* 修改所有节点的ewma值
*/
static void scale_active_circuits(ewfd_policy_data_t *pol,
                                  unsigned cur_tick)
{
  double factor;

  tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);

  factor =
    get_scale_factor(
      pol->active_circuit_pqueue_last_recalibrated,
      cur_tick);
  /** Ordinarily it isn't okay to change the value of an element in a heap,
   * but it's okay here, since we are preserving the order. */
  SMARTLIST_FOREACH_BEGIN(
      pol->active_circuit_pqueue,
      cell_ewfd_ewma_t *, e) {
    tor_assert(e->last_adjusted_tick ==
               pol->active_circuit_pqueue_last_recalibrated);
    e->cell_count *= factor;
    e->last_adjusted_tick = cur_tick;
  } SMARTLIST_FOREACH_END(e);
  pol->active_circuit_pqueue_last_recalibrated = cur_tick;
}

/** Have we initialized the ewma tick-counting logic? */
static int ewfd_ticks_initialized = 0;
/** At what monotime_coarse_t did the current tick begin? */
static monotime_coarse_t start_of_current_tick;
/** What is the number of the current tick? */
static unsigned current_tick_num;

// done
static inline unsigned int
cell_ewfd_get_tick(void)
{
  monotime_coarse_t now;
  monotime_coarse_get(&now);
  int32_t msec_diff = monotime_coarse_diff_msec32(&start_of_current_tick,
                                                  &now);
  return current_tick_num + msec_diff / (1000*ewfd_ewma_tick_len);
}


/** Adjust the global cell scale factor based on <b>options</b> */
void cmux_ewfd_set_options(const or_options_t *options, const networkstatus_t *consensus) {

}


void circuitmux_ewfd_free_all(void) {

}

// done
static circuitmux_policy_data_t * ewfd_alloc_cmux_data(circuitmux_t *cmux) {
  ewfd_policy_data_t *pol = NULL;

  tor_assert(cmux);

  pol = tor_malloc_zero(sizeof(*pol));
  pol->base_.magic = EWFD_POL_DATA_MAGIC;
  pol->active_circuit_pqueue = smartlist_new();
  pol->active_circuit_pqueue_last_recalibrated = cell_ewfd_get_tick();

  return TO_CMUX_POL_DATA(pol);
}

static void ewfd_free_cmux_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data) {
  ewfd_policy_data_t *ewma_pol = TO_EWFD_POL_DATA(pol_data);
  smartlist_free(ewma_pol->active_circuit_pqueue);
  tor_free(ewma_pol);
}

// done
static circuitmux_policy_circ_data_t *
ewfd_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                     circuit_t *circ, cell_direction_t direction,
                     unsigned int cell_count) {

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(direction == CELL_DIRECTION_OUT ||
             direction == CELL_DIRECTION_IN);
  (void)cell_count;

  ewfd_policy_circ_data_t *cdata = NULL;
  cdata = tor_malloc_zero(sizeof(*cdata));
  cdata->base_.magic = EWFD_POL_CIRC_DATA_MAGIC;
  cdata->circ = circ;

  // init cell_ewma_t
  cdata->cell_ewfd_ewma.last_adjusted_tick = cell_ewfd_get_tick();
  cdata->cell_ewfd_ewma.cell_count = 0.0;
  cdata->cell_ewfd_ewma.heap_index = -1;
  cdata->cell_ewfd_ewma.is_for_p_chan = (direction == CELL_DIRECTION_IN);

  return TO_CMUX_POL_CIRC_DATA(cdata);
}

static void
ewfd_free_circ_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data) {

}

// done
static void
ewfd_notify_circ_active(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data) {
  ewfd_policy_data_t *pol = NULL;
  ewfd_policy_circ_data_t *cdata = NULL;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  pol = TO_EWFD_POL_DATA(pol_data);
  cdata = TO_EWFD_POL_CIRC_DATA(pol_circ_data);

  if (cdata->cell_ewfd_ewma.heap_index != -1) {
    /* This circuit is already in the queue; remove it */
    remove_cell_ewfd(pol, &(cdata->cell_ewfd_ewma));
  }

  add_cell_ewfd(pol, &(cdata->cell_ewfd_ewma));
}

static void
ewfd_notify_circ_inactive(circuitmux_t *cmux,
                          circuitmux_policy_data_t *pol_data,
                          circuit_t *circ,
                          circuitmux_policy_circ_data_t *pol_circ_data) {
}

static void
ewfd_notify_xmit_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells) {
  ewfd_policy_data_t *pol = NULL;
  ewfd_policy_circ_data_t *cdata = NULL;
  unsigned int tick;
  double fractional_tick, ewma_increment;
  cell_ewfd_ewma_t *cell_ewma, *tmp;

  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);
  tor_assert(n_cells > 0);

  pol = TO_EWFD_POL_DATA(pol_data);
  cdata = TO_EWFD_POL_CIRC_DATA(pol_circ_data);

  /* Rescale the EWMAs if needed */
  tick = cell_ewfd_ewma_get_current_tick_and_fraction(&fractional_tick);

  if (tick != pol->active_circuit_pqueue_last_recalibrated) {
    scale_active_circuits(pol, tick);
  }

  /* How much do we adjust the cell count in cell_ewma by? */
  ewma_increment =
    ((double)(n_cells)) * pow(ewfd_ewma_scale_factor, -fractional_tick);

  /* Do the adjustment */
  cell_ewma = &(cdata->cell_ewfd_ewma);
  cell_ewma->cell_count += ewma_increment;

  /*
   * Since we just sent on this circuit, it should be at the head of
   * the queue.  Pop the head, assert that it matches, then re-add.
   */
  tmp = pop_first_cell_ewfd(pol);
  tor_assert(tmp == cell_ewma);
  add_cell_ewfd(pol, cell_ewma);
}

// done
static circuit_t *
ewfd_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data) {
  ewfd_policy_data_t *pol = NULL;
  circuit_t *circ = NULL;
  cell_ewfd_ewma_t *cell_ewfd_ewma = NULL;
  tor_assert(cmux);
  tor_assert(pol_data);

  pol = TO_EWFD_POL_DATA(pol_data);
  if (smartlist_len(pol->active_circuit_pqueue) > 0) {
    /* Get the head of the queue */
    cell_ewfd_ewma = smartlist_get(pol->active_circuit_pqueue, 0);
    circ = cell_ewfd_to_circuit(cell_ewfd_ewma);
  }

  EWFD_LOG("Picked circuit %p", circ);

  return circ;
}

static int
ewfd_cmp_cmux(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
              circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2) {
  return 0;
}
