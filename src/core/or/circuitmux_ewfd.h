#ifndef EWFD_CIRCUITMUX_EWFD_H_
#define EWFD_CIRCUITMUX_EWFD_H_

#include "core/or/or.h"
#include "core/or/circuitmux.h"

/* The public EWFD policy callbacks object. */
extern circuitmux_policy_t ewfd_ewma_policy;

extern circuitmux_policy_t ewfd_delay_policy;


/* Externally visible eWFD functions */
void cmux_ewfd_set_options(const or_options_t *options,
                           const networkstatus_t *consensus);

void circuitmux_ewfd_free_all(void);

#ifdef CIRCUITMUX_EWFD_PRIVATE

/*** EWFD structures ***/

typedef struct cell_ewfd_ewma_t cell_ewfd_ewma_t;
typedef struct ewfd_policy_data_t ewfd_policy_data_t;
typedef struct ewfd_policy_circ_data_t ewfd_policy_circ_data_t;

struct cell_ewfd_ewma_t {
  /** The last 'tick' at which we recalibrated cell_count.
   *
   * A cell sent at exactly the start of this tick has weight 1.0. Cells sent
   * since the start of this tick have weight greater than 1.0; ones sent
   * earlier have less weight. */
  uint32_t last_adjusted_tick;

  /** The EWMA of the cell count. */
  double cell_count;
  /** True iff this is the cell count for a circuit's previous
   * channel. */
  uint32_t is_for_p_chan : 1;
  /** The position of the circuit within the OR connection's priority
   * queue. */
  int heap_index;
};

typedef struct cell_ewfd_delay_t {
    /**
   * 基于delay来调度，检查一个时间range：
   * 方法-1. 优选选择包最多的队列
   * 方法-2. 优先发送下个发送ti更接近的队列，
   * 方法-3. 优先发送真实包最多的队列
   */
  uint64_t next_send_tick;
  uint32_t next_send_cnt; // next dump+real packet that need to be sent
  uint32_t all_real_pkt;  // all real packets on queue
  int heap_index;
} cell_ewfd_delay_t;

typedef struct ewfd_policy_data_t {
  circuitmux_policy_data_t base_;

  /**
   * Priority queue of cell_ewma_t for circuits with queued cells waiting
   * for room to free up on the channel that owns this circuitmux.  Kept
   * in heap order according to EWMA.  This was formerly in channel_t, and
   * in or_connection_t before that.
   */
  smartlist_t *active_circuit_pqueue;

  /**
   * The tick on which the cell_ewma_ts in active_circuit_pqueue last had
   * their ewma values rescaled.  This was formerly in channel_t, and in
   * or_connection_t before that.
   */
  unsigned int active_circuit_pqueue_last_recalibrated;
} ewfd_policy_data_t;

struct ewfd_policy_circ_data_t {
  circuitmux_policy_circ_data_t base_;

  /** ewma: 先发送之前发送包最少的队列
   */
  
  /**
   * The EWMA count for the number of cells flushed from this circuit
   * onto this circuitmux.  Used to determine which circuit to flush
   * from next.  This was formerly in circuit_t and or_circuit_t.
   */
  cell_ewfd_ewma_t cell_ewfd_ewma;

  /** settings for delay policy
   */
  cell_ewfd_delay_t cell_ewfd_delay;

  /**
   * Pointer back to the circuit_t this is for; since we're separating
   * out circuit selection policy like this, we can't attach cell_ewma_t
   * to the circuit_t any more, so we can't use SUBTYPE_P directly to a
   * circuit_t like before; instead get it here.
   */
  circuit_t *circ;
};

#define EWFD_POL_DATA_MAGIC 0x2fd8b16bU
#define EWFD_POL_CIRC_DATA_MAGIC 0x761e774cU

static inline ewfd_policy_data_t *
TO_EWFD_POL_DATA(circuitmux_policy_data_t *pol)
{
  if (!pol) return NULL;
  else {
    tor_assertf(pol->magic == EWFD_POL_DATA_MAGIC,
                "Mismatch: %"PRIu32" != %"PRIu32,
                pol->magic, EWFD_POL_DATA_MAGIC);
    return DOWNCAST(ewfd_policy_data_t, pol);
  }
}

static inline ewfd_policy_circ_data_t *
TO_EWFD_POL_CIRC_DATA(circuitmux_policy_circ_data_t *pol)
{
  if (!pol) return NULL;
  else {
    tor_assertf(pol->magic == EWFD_POL_CIRC_DATA_MAGIC,
                "Mismatch: %"PRIu32" != %"PRIu32,
                pol->magic, EWFD_POL_CIRC_DATA_MAGIC);
    return DOWNCAST(ewfd_policy_circ_data_t, pol);
  }
}


// ewfd_policy_circ_data_t

STATIC void cell_ewfd_ewma_initialize_ticks(void);
STATIC unsigned cell_ewfd_ewma_get_current_tick_and_fraction(double *remainder_out);

#endif //CIRCUITMUX_EWFD_PRIVATE

#endif //EWFD_CIRCUITMUX_EWFD_H_
