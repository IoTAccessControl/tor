#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_foreach.h"
#include "lib/time/compat_time.h"
#include "core/or/circuitmux.h"
#include <stdint.h>
#define CIRCUITMUX_EWFD_PRIVATE

#include "circuitmux_ewfd.h"
#include "feature/ewfd/debug.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include <math.h>


/**===============================================================================
 * EWFD Delay policy
 * ===============================================================================
 * 1 channel (policy_data) -> n circuits (policy_circ_data)
 */

/*** Circuitmux ewfd delay policy methods ***/
static circuitmux_policy_data_t * ewfd_delay_alloc_cmux_data(circuitmux_t *cmux);
static void ewfd_delay_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data);
static circuitmux_policy_circ_data_t *
ewfd_delay_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                     circuit_t *circ, cell_direction_t direction,
                     unsigned int cell_count);
static void
ewfd_delay_free_circ_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_delay_notify_circ_active(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_delay_notify_circ_inactive(circuitmux_t *cmux,
                          circuitmux_policy_data_t *pol_data,
                          circuit_t *circ,
                          circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_delay_set_n_cells(circuitmux_t *cmux,
                             circuitmux_policy_data_t *pol_data,
                             circuit_t *circ,
                             circuitmux_policy_circ_data_t *pol_circ_data,
                             unsigned int n_cells);
static void
ewfd_delay_notify_xmit_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells);
static circuit_t *
ewfd_delay_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data);
static int
ewfd_delay_cmp_cmux(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
              circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2);

/** 调度函数：
 */
static int compare_cell_ewfd_circ_delay(const void *p1, const void *p2)  {
  const cell_ewfd_delay_t *a = p1, *b = p2;
  if (a->all_real_pkt > b->all_real_pkt) {
    return -1;
  } else if (a->all_real_pkt < b->all_real_pkt) {
    return 1;
  }
  return 0;
}


circuitmux_policy_t ewfd_delay_policy = {
  /*.alloc_cmux_data =*/ ewfd_delay_alloc_cmux_data,
  /*.free_cmux_data =*/ ewfd_delay_free_cmux_data,
  /*.alloc_circ_data =*/ ewfd_delay_alloc_circ_data,
  /*.free_circ_data =*/ ewfd_delay_free_circ_data,
  /*.notify_circ_active =*/ ewfd_delay_notify_circ_active,
  /*.notify_circ_inactive =*/ ewfd_delay_notify_circ_inactive,
  /*.notify_set_n_cells =*/ ewfd_delay_set_n_cells, /* EWMA doesn't need this */
  /*.notify_xmit_cells =*/ ewfd_delay_notify_xmit_cells,
  /*.pick_active_circuit =*/ ewfd_delay_pick_active_circuit,
  /*.cmp_cmux =*/ ewfd_delay_cmp_cmux
};

static circuitmux_policy_data_t * ewfd_delay_alloc_cmux_data(circuitmux_t *cmux) {
  tor_assert(cmux);

  ewfd_policy_data_t *pol = tor_malloc_zero(sizeof(*pol));
  pol->base_.magic = EWFD_POL_DATA_MAGIC;
  pol->active_circuit_pqueue = smartlist_new();
  // pol->active_circuit_pqueue_last_recalibrated = (uint32_t) monotime_absolute_msec() / 1000;

  return TO_CMUX_POL_DATA(pol);
}

static void ewfd_delay_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data) {
  tor_assert(cmux);
  if (!pol_data) return;

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  smartlist_free(pol->active_circuit_pqueue);
  memwipe(pol, 0xda, sizeof(ewfd_policy_data_t));
  tor_free(pol);
}

static circuitmux_policy_circ_data_t *
ewfd_delay_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                     circuit_t *circ, cell_direction_t direction,
                     unsigned int cell_count) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);

  ewfd_policy_circ_data_t *pol_circ = tor_malloc_zero(sizeof(*pol_circ));
  pol_circ->base_.magic = EWFD_POL_CIRC_DATA_MAGIC;
  pol_circ->circ = circ;
  pol_circ->cell_ewfd_delay.heap_index = -1;

  return TO_CMUX_POL_CIRC_DATA(pol_circ);
}

static void ewfd_delay_free_circ_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  if (!pol_circ_data) return;
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);

  memwipe(circ_data, 0xdc, sizeof(ewfd_policy_circ_data_t));
  tor_free(circ_data);
}

static void ewfd_delay_notify_circ_active(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // add current circuit to active_circuit_pqueue heap
  // first remove then add
  if (circ_data->cell_ewfd_delay.heap_index != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue,
                      compare_cell_ewfd_circ_delay,
                      offsetof(cell_ewfd_delay_t, heap_index),
                      delay_item);
  }

  smartlist_pqueue_add(pol->active_circuit_pqueue,
                      compare_cell_ewfd_circ_delay,
                      offsetof(cell_ewfd_delay_t, heap_index),
                      delay_item);
}

static void ewfd_delay_notify_circ_inactive(circuitmux_t *cmux,
                          circuitmux_policy_data_t *pol_data,
                          circuit_t *circ,
                          circuitmux_policy_circ_data_t *pol_circ_data) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 删除并维持小根堆
  smartlist_pqueue_remove(pol->active_circuit_pqueue,
                      compare_cell_ewfd_circ_delay,
                      offsetof(cell_ewfd_delay_t, heap_index),
                      delay_item);
}

static void ewfd_delay_set_n_cells(circuitmux_t *cmux,
                             circuitmux_policy_data_t *pol_data,
                             circuit_t *circ,
                             circuitmux_policy_circ_data_t *pol_circ_data,
                             unsigned int n_cells) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 更新包数量
  // TODO： 1. 遍历发送队列来更新包数量 或者 2. 新api主动设置数量
  delay_item->all_real_pkt = n_cells;
  delay_item->next_send_cnt = n_cells;

  // 更新小根堆 pop -> push
  if (delay_item->heap_index != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue,
                        compare_cell_ewfd_circ_delay,
                        offsetof(cell_ewfd_delay_t, heap_index),
                        delay_item);
  }
  smartlist_pqueue_add(pol->active_circuit_pqueue,
                      compare_cell_ewfd_circ_delay,
                      offsetof(cell_ewfd_delay_t, heap_index),
                      delay_item);
}

// n_cells: 发送的包数量（dummy + real, 优先发real）
static void ewfd_delay_notify_xmit_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 更新包数量
  tor_assert(delay_item->next_send_cnt >= n_cells);
  delay_item->next_send_cnt -= n_cells;
  if (delay_item->all_real_pkt > n_cells) {
    delay_item->all_real_pkt -= n_cells;
  } else {
    delay_item->all_real_pkt = 0;
  }

  // 更新小根堆 pop -> push
  cell_ewfd_delay_t *tmp = smartlist_pqueue_pop(pol->active_circuit_pqueue,
                      compare_cell_ewfd_circ_delay,
                      offsetof(cell_ewfd_delay_t, heap_index));
  tor_assert(tmp == delay_item);
  smartlist_pqueue_add(pol->active_circuit_pqueue,
                      compare_cell_ewfd_circ_delay,
                      offsetof(cell_ewfd_delay_t, heap_index),
                      delay_item);
}

static circuit_t * ewfd_delay_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data) {
  tor_assert(cmux);
  tor_assert(pol_data);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  cell_ewfd_delay_t *delay_item = smartlist_pqueue_pop(pol->active_circuit_pqueue,
                                        compare_cell_ewfd_circ_delay,
                                        offsetof(cell_ewfd_delay_t, heap_index));
  ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(delay_item, ewfd_policy_circ_data_t, cell_ewfd_delay);
  tor_assert(circ_data);

  return circ_data->circ;
}

// 先发送包多的队列
static int ewfd_delay_cmp_cmux(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
              circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2) {
  tor_assert(cmux_1);
  tor_assert(pol_data_1);
  tor_assert(cmux_2);
  tor_assert(pol_data_2);

  ewfd_policy_data_t *pol_1 = TO_EWFD_POL_DATA(pol_data_1);
  ewfd_policy_data_t *pol_2 = TO_EWFD_POL_DATA(pol_data_2);

  int pkt_num_1 = 0, pkt_num_2 = 0;

  SMARTLIST_FOREACH_BEGIN(pol_1->active_circuit_pqueue, struct cell_ewfd_delay_t *, it) {
    pkt_num_1 += it->all_real_pkt;
  } SMARTLIST_FOREACH_END(it);

  SMARTLIST_FOREACH_BEGIN(pol_2->active_circuit_pqueue, struct cell_ewfd_delay_t *, it) {
    pkt_num_2 += it->all_real_pkt;
  } SMARTLIST_FOREACH_END(it);

  if (pkt_num_1 > pkt_num_2) {
    return 1;
  } else if (pkt_num_1 < pkt_num_2) {
    return -1;
  }

  return 0;
}

/**===============================================================================
 * EWFD EWMA policy
 * ===============================================================================
 */
/*** Static declarations for circuitmux_ewfd.c ewma policy***/

#define EWMA_TICK_LEN_DEFAULT 10
#define EWMA_TICK_LEN_MIN 1
#define EWMA_TICK_LEN_MAX 600
static int ewfd_ewma_tick_len = EWMA_TICK_LEN_DEFAULT;
static double ewfd_ewma_scale_factor = 0.1;

/** The default per-tick scale factor, if it hasn't been overridden by a
 * consensus or a configuration setting.  zero means "disabled". */
#define EWMA_DEFAULT_HALFLIFE 0.0

/*** Some useful constant #defines ***/

/** Any halflife smaller than this number of seconds is considered to be
 * "disabled". */
#define EPSILON 0.00001
/** The natural logarithm of 0.5. */
#define LOG_ONEHALF -0.69314718055994529

static void add_cell_ewfd_ewma(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma);
static int compare_cell_ewfd_ewma_counts(const void *p1, const void *p2);
static circuit_t * cell_ewfd_ewma_to_circuit(cell_ewfd_ewma_t *ewfd_conf);
static inline double get_ewma_scale_factor(unsigned from_tick, unsigned to_tick);
static cell_ewfd_ewma_t * pop_first_cell_ewma_ewfd(ewfd_policy_data_t *pol);
static void remove_cell_ewfd_ewma(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma);
static void scale_single_cell_ewfd_ewma(cell_ewfd_ewma_t *ewma, unsigned cur_tick);
static void scale_active_circuits_ewma(ewfd_policy_data_t *pol,
                                  unsigned cur_tick);

/*** Circuitmux ewfd_ewma policy methods ***/

static circuitmux_policy_data_t * ewfd_ewma_alloc_cmux_data(circuitmux_t *cmux);
static void ewfd_ewma_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data);
static circuitmux_policy_circ_data_t *
ewfd_alloc_circ_ewma_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                     circuit_t *circ, cell_direction_t direction,
                     unsigned int cell_count);
static void
ewfd_free_circ_ewma_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_notify_circ_ewma_active(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_notify_circ_ewma_inactive(circuitmux_t *cmux,
                          circuitmux_policy_data_t *pol_data,
                          circuit_t *circ,
                          circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewfd_notify_xmit_ewma_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells);
static circuit_t *
ewfd_pick_active_circuit_ewma(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data);
static int
ewfd_cmp_cmux_ewma(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
              circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2);

/*** EWFD circuitmux_policy_t method table ***/
circuitmux_policy_t ewfd_ewma_policy = {
  /*.alloc_cmux_data =*/ ewfd_ewma_alloc_cmux_data,
  /*.free_cmux_data =*/ ewfd_ewma_free_cmux_data,
  /*.alloc_circ_data =*/ ewfd_alloc_circ_ewma_data,
  /*.free_circ_data =*/ ewfd_free_circ_ewma_data,
  /*.notify_circ_active =*/ ewfd_notify_circ_ewma_active,
  /*.notify_circ_inactive =*/ ewfd_notify_circ_ewma_inactive,
  /*.notify_set_n_cells =*/ NULL, /* EWMA doesn't need this */
  /*.notify_xmit_cells =*/ ewfd_notify_xmit_ewma_cells,
  /*.pick_active_circuit =*/ ewfd_pick_active_circuit_ewma,
  /*.cmp_cmux =*/ ewfd_cmp_cmux_ewma
};


/** Have we initialized the ewma tick-counting logic? */
static int ewfd_ewma_ticks_initialized = 0;
/** At what monotime_coarse_t did the current tick begin? */
static monotime_coarse_t start_of_current_tick;
/** What is the number of the current tick? */
static unsigned current_tick_num;

/* EWMA helper functions */

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

/* 
*/
// done
static circuitmux_policy_data_t * ewfd_ewma_alloc_cmux_data(circuitmux_t *cmux) {
  ewfd_policy_data_t *pol = NULL;

  tor_assert(cmux);

  pol = tor_malloc_zero(sizeof(*pol));
  pol->base_.magic = EWFD_POL_DATA_MAGIC;
  pol->active_circuit_pqueue = smartlist_new();
  // pol->
  pol->active_circuit_pqueue_last_recalibrated = cell_ewfd_get_tick();

  return TO_CMUX_POL_DATA(pol);
}

// done
static void ewfd_ewma_free_cmux_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data) {
  ewfd_policy_data_t *pol = NULL;

  tor_assert(cmux);
  if (!pol_data) return;

  pol = TO_EWFD_POL_DATA(pol_data);

  smartlist_free(pol->active_circuit_pqueue);
  memwipe(pol, 0xda, sizeof(ewfd_policy_data_t));
  tor_free(pol);
}

// done
static circuitmux_policy_circ_data_t *
ewfd_alloc_circ_ewma_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
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

// done
static void
ewfd_free_circ_ewma_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data) {
  ewfd_policy_circ_data_t *cdata = NULL;

  tor_assert(cmux);
  tor_assert(circ);
  tor_assert(pol_data);

  if (!pol_circ_data) return;

  cdata = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  memwipe(cdata, 0xdc, sizeof(ewfd_policy_circ_data_t));
  tor_free(cdata);
}

// done
static void
ewfd_notify_circ_ewma_active(circuitmux_t *cmux,
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
    remove_cell_ewfd_ewma(pol, &(cdata->cell_ewfd_ewma));
  }

  add_cell_ewfd_ewma(pol, &(cdata->cell_ewfd_ewma));
}

// done
static void
ewfd_notify_circ_ewma_inactive(circuitmux_t *cmux,
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

  remove_cell_ewfd_ewma(pol, &(cdata->cell_ewfd_ewma));
}

// done
static void
ewfd_notify_xmit_ewma_cells(circuitmux_t *cmux,
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
    scale_active_circuits_ewma(pol, tick);
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
  tmp = pop_first_cell_ewma_ewfd(pol);
  tor_assert(tmp == cell_ewma);
  add_cell_ewfd_ewma(pol, cell_ewma);
}

/**
 * 
 */
static circuit_t *
ewfd_pick_active_circuit_ewma(circuitmux_t *cmux,
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
    circ = cell_ewfd_ewma_to_circuit(cell_ewfd_ewma);
  }

  EWFD_LOG("Picked circuit %p", circ);

  return circ;
}


// done
static int ewfd_cmp_cmux_ewma(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
              circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2) {
  ewfd_policy_data_t *p1 = NULL, *p2 = NULL;
  cell_ewfd_ewma_t *ce1 = NULL, *ce2 = NULL;

  tor_assert(cmux_1);
  tor_assert(pol_data_1);
  tor_assert(cmux_2);
  tor_assert(pol_data_2);

  p1 = TO_EWFD_POL_DATA(pol_data_1);
  p2 = TO_EWFD_POL_DATA(pol_data_2);

  if (p1 != p2) {
    /* Get the head cell_ewma_t from each queue */
    if (smartlist_len(p1->active_circuit_pqueue) > 0) {
      ce1 = smartlist_get(p1->active_circuit_pqueue, 0);
    }

    if (smartlist_len(p2->active_circuit_pqueue) > 0) {
      ce2 = smartlist_get(p2->active_circuit_pqueue, 0);
    }

    /* Got both of them? */
    if (ce1 != NULL && ce2 != NULL) {
      /* Pick whichever one has the better best circuit */
      return compare_cell_ewfd_ewma_counts(ce1, ce2);
    } else {
      if (ce1 != NULL) {
        /* We only have a circuit on cmux_1, so prefer it */
        return -1;
      } else if (ce2 != NULL) {
        /* We only have a circuit on cmux_2, so prefer it */
        return 1;
      } else {
        /* No circuits at all; no preference */
        return 0;
      }
    }
  } else {
    /* We got identical params */
    return 0;
  }
}

// done
static int compare_cell_ewfd_ewma_counts(const void *p1, const void *p2) 
{
  const cell_ewfd_ewma_t *ewma1 = p1, *ewma2 = p2;
  if (ewma1->cell_count < ewma2->cell_count)
    return -1;
  if (ewma1->cell_count > ewma2->cell_count)
    return 1;
  return 0;
}

// done
static circuit_t *
cell_ewfd_ewma_to_circuit(cell_ewfd_ewma_t *ewma)
{
  ewfd_policy_circ_data_t *cdata = NULL;

  tor_assert(ewma);
  cdata = SUBTYPE_P(ewma, ewfd_policy_circ_data_t, cell_ewfd_ewma);
  tor_assert(cdata);

  return cdata->circ;
}


/* ==== Functions for scaling cell_ewma_t ==== */


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

// ignore: get_circuit_priority_halflife

/** Adjust the global cell scale factor based on <b>options</b> */
void cmux_ewfd_set_options(const or_options_t *options, const networkstatus_t *consensus) {
  //   double halflife_default =
    // ((double) CMUX_PRIORITY_HALFLIFE_MSEC_DEFAULT) / 1000.0;
  cell_ewfd_ewma_initialize_ticks();
  ewfd_ewma_scale_factor = exp(LOG_ONEHALF / 30);
  ewfd_ewma_tick_len = EWMA_TICK_LEN_DEFAULT;
  log_info(LD_OR,
           "Enabled cell_ewma algorithm "
           "scale factor is %f per %d seconds",
            ewfd_ewma_scale_factor, ewfd_ewma_tick_len);
}

static inline double get_ewma_scale_factor(unsigned from_tick, unsigned to_tick)
{
  return pow(ewfd_ewma_scale_factor, to_tick - from_tick);
}


/* 修改所有节点的ewma值
*/
static void scale_active_circuits_ewma(ewfd_policy_data_t *pol,
                                  unsigned cur_tick)
{
  double factor;

  tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);

  factor =
    get_ewma_scale_factor(
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


static void add_cell_ewfd_ewma(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma)
{
  tor_assert(pol);
  tor_assert(ewma);

  scale_single_cell_ewfd_ewma(ewma,
      pol->active_circuit_pqueue_last_recalibrated);

  smartlist_pqueue_add(pol->active_circuit_pqueue,
                       compare_cell_ewfd_ewma_counts,
                       offsetof(cell_ewfd_ewma_t, heap_index),
                       ewma);
  EWFD_LOG("Added circuit %p", cell_ewfd_ewma_to_circuit(ewma));
}

// done
static void remove_cell_ewfd_ewma(ewfd_policy_data_t *pol, cell_ewfd_ewma_t *ewma)
{
  tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);
  tor_assert(ewma);
  tor_assert(ewma->heap_index != -1);

  smartlist_pqueue_remove(pol->active_circuit_pqueue,
                          compare_cell_ewfd_ewma_counts,
                          offsetof(cell_ewfd_ewma_t, heap_index),
                          ewma);
}

static cell_ewfd_ewma_t * pop_first_cell_ewma_ewfd(ewfd_policy_data_t *pol)
{
    tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);

  return smartlist_pqueue_pop(pol->active_circuit_pqueue,
                              compare_cell_ewfd_ewma_counts,
                              offsetof(cell_ewfd_ewma_t, heap_index));
}

static void scale_single_cell_ewfd_ewma(cell_ewfd_ewma_t *ewma, unsigned cur_tick)
{
  double factor = get_ewma_scale_factor(ewma->last_adjusted_tick, cur_tick);
  ewma->cell_count *= factor;
  ewma->last_adjusted_tick = cur_tick;
}

void circuitmux_ewfd_free_all(void) {
  ewfd_ewma_ticks_initialized = 0;
}
