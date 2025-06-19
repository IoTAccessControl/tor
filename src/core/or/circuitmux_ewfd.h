#ifndef EWFD_CIRCUITMUX_EWFD_H_
#define EWFD_CIRCUITMUX_EWFD_H_

#include "core/or/or.h"
#include "core/or/circuitmux.h"
#include <stdint.h>

/* The public EWFD policy callbacks object. */
extern circuitmux_policy_t ewfd_delay_policy;

circuitmux_policy_t* ewfd_get_mux_policy(void);

// need wait ?
bool circuitmux_set_advance_delay(circuit_t *circ, uint64_t gap_ti_ms, uint32_t pkt_num);

enum EWFDDelayMODE {
  EWFD_MODE_NORMAL, // 直接send，不管模式
  EWFD_MODE_WAIT_TO_BURST, // gap -> 等待burst
  EWFD_MODE_BURST,
  EWFD_MODE_GAP,
};

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

/**
* 基于delay来调度，检查一个时间range：
* 方法-1. 优选选择包最多的队列
* 方法-2. 优先发送下个发送ti更接近的队列，
* 方法-3. 优先发送真实包最多的队列
*/
typedef struct cell_ewfd_delay_t {
  /*
  * delay模式：发送完n个包，gap t ms。
  * burst_finish_ti + gap_ti，再次进入burst
  */
  // 上一个burst结束的时间
  uint64_t burst_finish_ti; 
  // gap结束的时间
  uint64_t gap_ti; // after burst sleep for this duration
  // add delay事件时，设置n个包
  uint32_t burst_send_cnt; // next dump+real packet that need to be sent (一开始设置)
  // 发送一个包就+1
  uint32_t cur_send_cnt; // how many pkt are send now (add)
  // 由发送时对列上现有包数量来决定 （只用来调度）
  uint32_t remain_real_pkt;  // remain real packets on queue ()
  uint8_t delay_state; // burst or gap

  int heap_index;
  int sleep_hindex;
} cell_ewfd_delay_t;

/* circuitmux_t 保存多个circuit, 用policy记录这些circuit，每个circuit有自己的policy
 * 为支持delay，每个circuit保存一个burst_ti, pkt_num。在不到burst_ti之前不会发送。
 * active/inactive的逻辑不变。
*/
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
   * For delay based WP defense, we need to make the circuit sleep for a while to make a GAP after a burst stream.
   */
  smartlist_t *sleep_circuit_pqueue;

  /**
   * The tick on which the cell_ewma_ts in active_circuit_pqueue last had
   * their ewma values rescaled.  This was formerly in channel_t, and in
   * or_connection_t before that.
   */
  // unsigned int active_circuit_pqueue_last_recalibrated;
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
  // cell_ewfd_ewma_t cell_ewfd_ewma;

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
