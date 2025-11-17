
#define CIRCUITMUX_PRIVATE
#include "core/or/circuitmux.h"
#define EWFD_USE_TEMP_LOG
#include "feature/ewfd/debug.h"
#define CIRCUITMUX_EWFD_PRIVATE
#include "circuitmux_ewfd.h"

#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_foreach.h"
#include "lib/time/compat_time.h"
#include "core/or/or.h"
#include "core/or/circuitlist.h"
#include "core/or/scheduler.h"
#include <stdbool.h>
#include <sys/types.h>



#include "core/or/circuit_st.h"
#include "core/or/channel.h"
#include "core/or/or_circuit_st.h"
#include <stdint.h>





#include "feature/ewfd/ewfd_op.h"
#include "lib/crypt_ops/crypto_util.h"

extern circuitmux_policy_t ewma_policy;

circuitmux_policy_t* ewfd_get_mux_policy(void) {
  // return &ewma_policy;
  return &ewfd_delay_policy;
}

/**===============================================================================
 * EWFD Delay policy
 * ===============================================================================
 * 1 channel (policy_data) -> n circuits (policy_circ_data)
 * 
 * delay实现原理：
 * active_queue (brust): 发送中 
 * sleep_queue (gap): 发送完，等待继续
 *
 * mode: NORMAL，一直发，优先发包最少的
 * mode: Burst
 *    cur_send >= burst_send，移到sleep
 * mode: GAP
 *    
 *===============================================================================
 * EWFD Dummy Packet policy
 * ===============================================================================
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

static int compare_cell_ewfd_active_circ(const void *p1, const void *p2);
static int compare_cell_ewfd_sleep_circ(const void *p1, const void *p2);

static void ewfd_add_to_active_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item);
static void ewfd_add_to_inactive_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item);
static void ewfd_remove_active_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *item);
static void ewfd_remove_inactive_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *ewfd_item);
static int ewfd_get_cell_on_queue(circuit_t *circ);
static const char* get_delay_state_string(int delay_state);
static void ewfd_log_all_queue_circuits(ewfd_policy_data_t *pol, const char *context);

static void ewfd_cmux_revoke_inactive_queue(cell_ewfd_delay_t *delay_item, circuit_t *circ, ewfd_policy_data_t *pol, channel_t *chan); 

static void ewfd_send_dummy_packet(circuit_t *circ, cell_ewfd_delay_t *delay_item);

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

/*
方案-1-补丁：在set_advance delay时另外发包唤醒队列
包如果进入了gap，就加入到sleep队列。circ null, 整个chan不被调度（scheduler->waint_cells）

预期效果：就算移到了队列外面，也会被唤醒。应该能正常发完包，不会被影响。  
pick_active: 从active queue poll
xmit_cell: 状态检查，burst -> gap
set_num: 什么也不做（后面：gap -> burst, 将sleep -> active）

set_advance_delay: 
burst: 
- 没包：发送一个包
- 有包：移到active_queue，并且唤醒调度 
gap: 
- 更新时间

*/


static inline circuitmux_t* ewfd_get_cmux_from_circ(circuit_t *circ) {
  channel_t *chan = NULL;


  if (circ->magic == OR_CIRCUIT_MAGIC) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    chan = or_circ->p_chan;
  } else if (circ->magic == ORIGIN_CIRCUIT_MAGIC) {
    chan = circ->n_chan;
  } else { // is release
    return NULL;
  }

  tor_assert(chan);

  return chan->cmux;
}


static int ewfd_cmux_idx = 0;
static circuitmux_policy_data_t * ewfd_delay_alloc_cmux_data(circuitmux_t *cmux) {
  tor_assert(cmux);

  ewfd_policy_data_t *pol = tor_malloc_zero(sizeof(*pol));
  pol->base_.magic = EWFD_POL_DATA_MAGIC;
  pol->active_circuit_pqueue = smartlist_new();
  pol->inactive_circuit_pqueue = smartlist_new();
  pol->idx = ewfd_cmux_idx++;
  return TO_CMUX_POL_DATA(pol);
}

static void ewfd_delay_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data) {
  tor_assert(cmux);
  if (!pol_data) return;

  EWFD_LOG("Free policy cmux: %p", cmux);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  smartlist_free(pol->active_circuit_pqueue);
  smartlist_free(pol->inactive_circuit_pqueue);
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
  pol_circ->cell_ewfd_delay.delay_state = EWFD_MODE_NORMAL;
  pol_circ->cell_ewfd_delay.active_hindex = -1;
  pol_circ->cell_ewfd_delay.inactive_hindex = -1;

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
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);

  // TODO: 
  EWFD_LOG("[delay-event] step:free-policy circ:%d", ewfd_get_circuit_id(circ));
  // remove pol from queues
  ewfd_remove_active_item(pol, &circ_data->cell_ewfd_delay);
  ewfd_remove_inactive_item(pol, &circ_data->cell_ewfd_delay);

  ewfd_log_all_queue_circuits(pol, "[delay-event] free-policy");

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


  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    // EWFD_LOG("[delay-event] step:add_to_active_queue circ:%d state:%s", ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state));
    ewfd_add_to_active_queue(pol, delay_item);
    return;
  }

  // 如果来包了，也唤醒，主要是在trigger_inactive中唤醒
  if (delay_item->delay_state == EWFD_MODE_GAP) {
    uint64_t cur_ti = monotime_absolute_msec();
    uint64_t gap_finish_ti = delay_item->burst_finish_ti + delay_item->gap_ti;
    if (gap_finish_ti <= cur_ti) {
      delay_item->delay_state = EWFD_MODE_BURST;
    }
  }

  // add current circuit to active_circuit_pqueue heap
  if (delay_item->delay_state == EWFD_MODE_BURST) {
    // EWFD_LOG("[delay-event] step:add_to_active_queue circ:%d state:%s", ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state));
    ewfd_add_to_active_queue(pol, delay_item);
  } 
  else if (delay_item->delay_state == EWFD_MODE_GAP || delay_item->delay_state == EWFD_MODE_WAIT_TO_BURST) {
    // EWFD_LOG("[delay-event] step:add_to_sleep_queue circ:%d state:%s", ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state));
    ewfd_add_to_inactive_queue(pol, delay_item);
  }     

  ewfd_log_all_queue_circuits(pol, "[delay-event] active");
}

/*
* 正常情况应该detach的时候，或者已经发送完的时候，才需要inactive
* inactive > sleep, inactive的时候需要将sleep中的item也移除
*/
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

  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    ewfd_remove_active_item(pol, delay_item);
    return;
  }

  // 包全部发送完才会inactive  
  // tor_assert(delay_item->burst_send_cnt <= delay_item->cur_send_cnt);

  // EWFD_TEMP_LOG("[delay-event] step:inactive circ:%d alen:%d slen:%d burst:%u send:%u remain:%u state:%s", ewfd_get_circuit_id(circ),
  //   smartlist_len(pol->active_circuit_pqueue), smartlist_len(pol->sleep_circuit_pqueue), 
  //   delay_item->burst_send_cnt, delay_item->cur_send_cnt, delay_item->remain_real_pkt, get_delay_state_string(delay_item->delay_state));

  
  // remove from queues
  ewfd_add_to_inactive_queue(pol, delay_item);
  
  ewfd_log_all_queue_circuits(pol, "[delay-event] inactive");
}

/* 发送之前和之后调用
* set_num: 仅更新包数量，修正状态, BURST -> GAP 
* GAP -> Burst，active里面检查
*/
static void ewfd_delay_set_n_cells(circuitmux_t *cmux,
                             circuitmux_policy_data_t *pol_data,
                             circuit_t *circ,
                             circuitmux_policy_circ_data_t *pol_circ_data,
                             unsigned int n_cells) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  // // is free
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  // if (pol->base_.magic != EWFD_POL_DATA_MAGIC) {
  //   return;
  // }

  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 更新包数量：由queue中包的数量来自动更新
  delay_item->remain_real_pkt = n_cells;


  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    return;
  }

  if (delay_item->delay_state == EWFD_MODE_BURST) {
    if (delay_item->cur_send_cnt >= delay_item->burst_send_cnt) {
      // EWFD_TEMP_LOG("[delay-event] step:deactive_circ cric:%d switch:%s", circ->n_circ_id, get_delay_state_string(EWFD_MODE_GAP));
      delay_item->delay_state = EWFD_MODE_GAP;
      delay_item->burst_send_cnt = 0;
      delay_item->cur_send_cnt = 0;
      ewfd_add_to_inactive_queue(pol, delay_item);
    }
  }
}

// n_cells: 发送的包数量（dummy + real, 优先发real），发送完调用
/**
 * 统一在set_num中处理，这里不再更新状态
 */
static void ewfd_delay_notify_xmit_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells) {
  tor_assert(cmux);
  tor_assert(pol_data);
  tor_assert(circ);
  tor_assert(pol_circ_data);

  // ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 更新包数量
  delay_item->cur_send_cnt += n_cells;
  delay_item->remain_real_pkt -= n_cells;

  // NORMAL mode不需要管delay  
  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    return;
  }

  // update burst_finish_ti of each cell
  delay_item->burst_finish_ti = monotime_absolute_msec();

  // EWFD_TEMP_LOG("[delay-event] step:xmit_cell circ:%d n_cell:%u burst:%u cur:%u state:%s", ewfd_get_circuit_id(circ), n_cells, 
  //   delay_item->burst_send_cnt, delay_item->cur_send_cnt, get_delay_state_string(delay_item->delay_state));

  // gap -> finish -> normal
}

/* 返回时间到了发送界限，并且有真实包的对列
* 需要考虑普通模式，没有BURST/GAP
*/
static circuit_t * ewfd_delay_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data) {
  tor_assert(cmux);
  tor_assert(pol_data);
  circuit_t *circ = NULL;

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  // Log all circuits in queues before processing
  ewfd_log_all_queue_circuits(pol, "[delay-event] pick_active queue");

  /*
  * 从inactive queue唤醒一个 delay_item
  */
  // TODO: Implement inactive queue wakeup logic

  // DEAD_CIRCUIT_MAGIC, pick的已经free (circuit_free_)
  if (smartlist_len(pol->active_circuit_pqueue) > 0) {
    cell_ewfd_delay_t *delay_item = smartlist_get(pol->active_circuit_pqueue, 0);
    ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(delay_item, ewfd_policy_circ_data_t, cell_ewfd_delay);
    tor_assert(circ_data);
    circ = circ_data->circ;

    // 当前触发pick的是gap队列，就返回NULL circ
    // 任何时候不应该poll 到数量为0的circ
    if (delay_item->remain_real_pkt == 0) {
      ewfd_log_all_queue_circuits(pol, "[delay-event] pick_active_no_cell");
      tor_assert(false);
    }
  } else {
    EWFD_TEMP_LOG("[delay-event] step:pick_active_no_circ");
  }

  // tor_assert(circ);
  if (circ == NULL) {
    ewfd_log_all_queue_circuits(pol, "[delay-event] pick_active_no_circ");
    // tor_assert(circ);
  }
 
  return circ;
}

// 同时只能在一个对列，先检查是否存在
static void ewfd_add_to_active_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item) {
  if (item->active_hindex != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue, compare_cell_ewfd_active_circ,
      offsetof(cell_ewfd_delay_t, active_hindex), item);
  }
  if (item->inactive_hindex != -1) {
    smartlist_pqueue_remove(pol->inactive_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, inactive_hindex), item);
  }
  tor_assert(item->delay_state == EWFD_MODE_NORMAL || item->delay_state == EWFD_MODE_BURST);
  smartlist_pqueue_add(pol->active_circuit_pqueue, compare_cell_ewfd_active_circ,
    offsetof(cell_ewfd_delay_t, active_hindex), item);
}


static void ewfd_add_to_inactive_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item)
{
  if (item->active_hindex != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue, compare_cell_ewfd_active_circ,
      offsetof(cell_ewfd_delay_t, active_hindex), item);
  }
  if (item->inactive_hindex != -1) {
    smartlist_pqueue_remove(pol->inactive_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, inactive_hindex), item);
  }
  smartlist_pqueue_add(pol->inactive_circuit_pqueue, compare_cell_ewfd_sleep_circ,
    offsetof(cell_ewfd_delay_t, inactive_hindex), item);
}

static void ewfd_remove_active_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *ewfd_item) {
    tor_assert(pol);
    tor_assert(pol->active_circuit_pqueue);
    tor_assert(ewfd_item);
    if (ewfd_item->active_hindex != -1) {
      smartlist_pqueue_remove(pol->active_circuit_pqueue,
                          compare_cell_ewfd_active_circ,
                          offsetof(cell_ewfd_delay_t, active_hindex),
                          ewfd_item);
    }
    // ewfd_log_all_queue_circuits(pol, "[delay-event] remove_active_item");
}

static void ewfd_remove_inactive_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *ewfd_item)
{
  tor_assert(pol);
  tor_assert(pol->inactive_circuit_pqueue);
  tor_assert(ewfd_item);
  if (ewfd_item->inactive_hindex != -1) {
    smartlist_pqueue_remove(pol->inactive_circuit_pqueue,
                        compare_cell_ewfd_sleep_circ,
                        offsetof(cell_ewfd_delay_t, inactive_hindex), ewfd_item);
  }
}

/* 需要考虑没有设置burst，那么cur_send_cnt会一直增加  
* 1. 先发送真实包多的队列
* cur_send_pkt, burst_send_cnt, 先发left最少的
*/
static int compare_cell_ewfd_active_circ(const void *p1, const void *p2) {
  const cell_ewfd_delay_t *a = p1, *b = p2;

  // 
  if (a->remain_real_pkt > b->remain_real_pkt) {
    return -1;
  } else {
    return 1;
  }

  // 普通模式，先发真实包少的队列
  // if (a->delay_state == EWFD_MODE_NORMAL || b->delay_state == EWFD_MODE_NORMAL) {
  //   if (a->remain_real_pkt > b->remain_real_pkt) {
  //     return -1;
  //   }
  //   return 1;
  // }

  // // burst mode
  // if (a->delay_state == EWFD_MODE_BURST && b->delay_state != EWFD_MODE_BURST) {
  //   return 1;
  // }
  // if (b->delay_state == EWFD_MODE_BURST && a->delay_state != EWFD_MODE_BURST) {
  //   return -1;
  // }
  // // tor_assert(a->delay_state == EWFD_MODE_BURST || b->delay_state == EWFD_MODE_BURST);
  // tor_assert(a->burst_send_cnt >= a->cur_send_cnt);
  // tor_assert(b->burst_send_cnt >= b->cur_send_cnt);

  // uint32_t a_remain = a->burst_send_cnt - a->cur_send_cnt;
  // uint32_t b_remain = b->burst_send_cnt - b->cur_send_cnt;
  // // EWFD_LOG("cur: %u burst: %u", a->cur_send_cnt, a->burst_send_cnt);

  // if (a_remain < b_remain) {
  //   return 1;
  // } else if (a_remain > b_remain) {
  //   return -1;
  // }
  // return 0;
}

/*
*  1. 发送时间更接近的
*/
static int compare_cell_ewfd_sleep_circ(const void *p1, const void *p2) {
  const cell_ewfd_delay_t *a = p1, *b = p2;
  uint64_t a_gap_finish_ti = a->burst_finish_ti + a->gap_ti;
  uint64_t b_gap_finish_ti = b->burst_finish_ti + b->gap_ti;
  if (a_gap_finish_ti < b_gap_finish_ti) {
    return 1;
  } else if (a_gap_finish_ti > b_gap_finish_ti) {
    return 0;
  }
  return 0;
}

/* 对列选取
*  1. 选取真实包最多的  
*/
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
    pkt_num_1 += it->remain_real_pkt;
  } SMARTLIST_FOREACH_END(it);

  SMARTLIST_FOREACH_BEGIN(pol_2->active_circuit_pqueue, struct cell_ewfd_delay_t *, it) {
    pkt_num_2 += it->remain_real_pkt;
  } SMARTLIST_FOREACH_END(it);

  if (pkt_num_1 > pkt_num_2) {
    return 1;
  } else if (pkt_num_1 < pkt_num_2) {
    return -1;
  }

  return 0;
}



static const char* get_delay_state_string(int delay_state) 
{
  switch (delay_state) {
    case EWFD_MODE_NORMAL:
      return "NORMAL";
    case EWFD_MODE_WAIT_TO_BURST:
      return "WAIT_TO_BURST";
    case EWFD_MODE_BURST:
      return "BURST";
    case EWFD_MODE_GAP:
      return "GAP";
  } 
  return "UNKNOWN";
}

/* API 语义： 发送完pkt_num个包，gap一段时间。
* 
* @ return is_handled: true false
* 方案-1: 唤醒gap/burst忙等队列
burst: pkt=0, 发送一个包。pkt=1, active队列，唤醒kschduler
gap: pkt=0, 更新时间。gap的队列不应该出现在active_queue中，但是往gap队列加包，仍然会触发pick_active，如果没有别的active circ,此时应该是NULL circ。
*/
bool circuitmux_set_advance_delay(circuit_t *circ, uint64_t gap_ti_ms, uint32_t pkt_num) {
  channel_t *chan = NULL;

  // EWFD_LOG("circuitmux_set_advance_delay: %lu %u", gap_ti_ms, pkt_num);
  // return false;

  if (circ->magic == OR_CIRCUIT_MAGIC) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    chan = or_circ->p_chan;
  } else if (circ->magic == ORIGIN_CIRCUIT_MAGIC) {
    chan = circ->n_chan;
  } else { // is release
    EWFD_LOG("release circuitmux_set_advance_delay: %p", circ);
    return true;
  }

  tor_assert(chan);
  /*
  * 为啥circ_data delete了，这里还能用
  */

  circuitmux_t *cmux = chan->cmux;
  circuitmux_policy_circ_data_t* circ_policy = circuitmux_find_circ_policy(cmux, circ);
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(cmux->policy_data);
  tor_assert(circ_policy);

  /*
  * 前面增加Dummy包的防御，Dummy包也被认为是真实包，目前没法区分队列上真实包究竟有多少
  */
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(circ_policy);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  if (delay_item->delay_state == EWFD_MODE_DESTROY) {
    // EWFD_TEMP_LOG("[delay-event] step:advanve_delay_destroy_to_burst circ:%d burst:%u remain:%u", 
    //   ewfd_get_circuit_id(circ), pkt_num, delay_item->remain_real_pkt);
    tor_assert(0);
    return true;
  }


  /* 第一次不gap,直接发送
  */
  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    // EWFD_TEMP_LOG("[delay-event] step:advanve_delay_normal_to_burst circ:%d burst:%u remain:%u state:%s active:%d sleep:%d", 
    //   ewfd_get_circuit_id(circ), pkt_num, delay_item->remain_real_pkt, get_delay_state_string(EWFD_MODE_BURST), 
    //   delay_item->active_hindex != -1);
    delay_item->delay_state = EWFD_MODE_BURST;
    delay_item->gap_ti = gap_ti_ms;
    delay_item->burst_send_cnt = pkt_num;
    delay_item->cur_send_cnt = 0;
    delay_item->burst_finish_ti = monotime_absolute_msec();
    return true;
  }

  uint64_t cur_ti = monotime_absolute_msec();
  uint64_t gap_finish_ti = delay_item->burst_finish_ti + gap_ti_ms;
  if (delay_item->delay_state == EWFD_MODE_GAP) {
    if (gap_finish_ti <= cur_ti) {
      // EWFD_TEMP_LOG("[delay-event] step:set_advance_delay circ:%d state:%s->%s li:%d", 
      //   ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state), "WAIT_TO_BURST", __LINE__);
      delay_item->delay_state = EWFD_MODE_WAIT_TO_BURST;
    }
  }

  EWFD_LOG("[delay-event] step:advance_delay cmux-id:%d circ:%d state:%s gap:%lu cur_ti:%lu want:%u cur:%u burst:%u remain:%u in_active:%d, in_sleep:%d", 
      pol->idx, ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state), gap_finish_ti, cur_ti, 
      pkt_num, delay_item->cur_send_cnt, delay_item->burst_send_cnt, delay_item->remain_real_pkt, 
      delay_item->active_hindex != -1);

  // 上次gap是否结束
  if (delay_item->delay_state != EWFD_MODE_WAIT_TO_BURST) {
    // should wait
    // EWFD_TEMP_LOG("[delay-event] step:set_advance_delay status:should-wait cmux-id:%d circ:%d cur:%u burst:%u remain:%u state:%s last_burst:%lu next_burst:%lu cur_ti:%lu",
    //   pol->idx, ewfd_get_circuit_id(circ), delay_item->cur_send_cnt, delay_item->burst_send_cnt, delay_item->remain_real_pkt, 
    //   get_delay_state_string(delay_item->delay_state), delay_item->burst_finish_ti, delay_item->burst_finish_ti + gap_ti_ms, cur_ti);
    return false;
  }

  EWFD_TEMP_LOG("[delay-state] step:advance_delay_trigger cmux:%p cmux-id:%d circ:%d state:%s->%s cur:%u burst:%u remain:%u", cmux, pol->idx, ewfd_get_circuit_id(circ), 
    get_delay_state_string(delay_item->delay_state), "BURST", delay_item->cur_send_cnt, delay_item->burst_send_cnt, delay_item->remain_real_pkt);
  
  delay_item->delay_state = EWFD_MODE_BURST;
  delay_item->gap_ti = gap_ti_ms;
  delay_item->cur_send_cnt = 0;
  delay_item->burst_send_cnt = pkt_num;

  // 由WAIT_TO_BURST唤醒, 需要从inactive队列中拉出来
  ewfd_cmux_revoke_inactive_queue(delay_item, circ, pol, chan);

  return true;
}

/*
* 基本逻辑：
* 1. 检查gap是否结束，以及是否需要唤醒  
* 2. 对于没有包的burst队列，发送一个dummy包  
* @return true: should release
*/
bool circuitmux_trigger_inactive_circ(circuit_t *circ, uint64_t tick_ms)
{
  channel_t *chan = NULL;

  if (circ->magic == OR_CIRCUIT_MAGIC) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    chan = or_circ->p_chan;
  } else if (circ->magic == ORIGIN_CIRCUIT_MAGIC) {
    chan = circ->n_chan;
  } else { // is release
    return true;
  }

  tor_assert(chan);

  circuitmux_t *cmux = chan->cmux;
  tor_assert(cmux);

  circuitmux_policy_circ_data_t* circ_policy = circuitmux_find_circ_policy(cmux, circ);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(cmux->policy_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(circ_policy);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 不再需要检查
  if (delay_item->delay_state == EWFD_MODE_DESTROY || delay_item->delay_state == EWFD_MODE_NORMAL) {
    EWFD_TEMP_LOG("[delay-event] step:trigger_event-release circ:%d state:%s li:%d", 
      ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state), __LINE__);
    return true;
  }

  EWFD_TEMP_LOG("[delay-event] step:trigger_event circ:%d state:%s li:%d", 
    ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state), __LINE__);

  ewfd_log_all_queue_circuits(pol, "[delay-event] trigger_event");

  // 检查gap是否结束
  /*
  GAP结束，如何退出？
  GAP结束了，不再trigger-event?
  */
  uint64_t cur_ti = monotime_absolute_msec();
  if (delay_item->delay_state == EWFD_MODE_GAP) {
    uint64_t gap_finish_ti = delay_item->burst_finish_ti + delay_item->gap_ti;
    if (gap_finish_ti <= cur_ti) {
      delay_item->delay_state = EWFD_MODE_WAIT_TO_BURST;
    }
  }

  // wait_to_burst 啥都不做
  if (delay_item->delay_state == EWFD_MODE_WAIT_TO_BURST) {
    // 已经结束，set_advance已经不调用
    uint64_t gap_finish_ti = delay_item->burst_finish_ti + delay_item->gap_ti;
    if (gap_finish_ti + 500 <= cur_ti) {
      delay_item->delay_state = EWFD_MODE_NORMAL;

      if (delay_item->remain_real_pkt == 0) {
        ewfd_remove_active_item(pol, delay_item);
        ewfd_remove_inactive_item(pol, delay_item);
      } else {
        ewfd_add_to_active_queue(pol, delay_item);
        scheduler_channel_has_waiting_cells(chan);
      }
      return true;
    }
    return false;
  }

  if (delay_item->delay_state == EWFD_MODE_BURST) {
    EWFD_TEMP_LOG("[delay-event] step:trigger_event-trigger circ:%d state:%s remain:%u cur:%u burst:%u ti:%lu li:%d", 
      ewfd_get_circuit_id(circ), get_delay_state_string(delay_item->delay_state), 
      delay_item->remain_real_pkt, delay_item->cur_send_cnt, delay_item->burst_send_cnt, cur_ti, __LINE__);
     // add dummy packet
    if (delay_item->burst_send_cnt > delay_item->cur_send_cnt && delay_item->remain_real_pkt == 0) {
      ewfd_send_dummy_packet(circ, delay_item);
    } 
    if (delay_item->inactive_hindex != -1) {
      // 唤醒调度
      ewfd_add_to_active_queue(pol, delay_item);
      scheduler_channel_has_waiting_cells(chan);
    }
  }


  return false;
}

static int ewfd_get_cell_on_queue(circuit_t *circ) {
  cell_queue_t *queue = NULL;
  if (circ->magic == OR_CIRCUIT_MAGIC) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    queue = &or_circ->p_chan_cells;
  } else {
    queue = &circ->n_chan_cells;
  }
  return queue->n;
}

static void ewfd_log_all_queue_circuits(ewfd_policy_data_t *pol, const char *context) {
#ifdef EWFD_TEMP_LOG
  char active_circs[512] = {0};
  char inactive_circs[512] = {0};
  int active_pos = 0, inactive_pos = 0;
  
  // Build active queue circuit list
  SMARTLIST_FOREACH_BEGIN(pol->active_circuit_pqueue, cell_ewfd_delay_t *, it) {
    ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(it, ewfd_policy_circ_data_t, cell_ewfd_delay);
    if (circ_data && circ_data->circ) {
      int written = snprintf(active_circs + active_pos, sizeof(active_circs) - active_pos, 
                           "%d(%s,%u/%u,%u),", ewfd_get_circuit_id(circ_data->circ), 
                           get_delay_state_string(it->delay_state),
                           it->cur_send_cnt, it->burst_send_cnt, it->remain_real_pkt);
      if (written > 0 && active_pos + written < sizeof(active_circs)) {
        active_pos += written;
      }
    }
  } SMARTLIST_FOREACH_END(it);

  SMARTLIST_FOREACH_BEGIN(pol->inactive_circuit_pqueue, cell_ewfd_delay_t *, it) {
    ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(it, ewfd_policy_circ_data_t, cell_ewfd_delay);
    if (circ_data && circ_data->circ) {
      int written = snprintf(inactive_circs + inactive_pos, sizeof(inactive_circs) - inactive_pos, 
                           "%d(%s,%u/%u,%u),", ewfd_get_circuit_id(circ_data->circ), 
                           get_delay_state_string(it->delay_state), it->cur_send_cnt, it->burst_send_cnt, it->remain_real_pkt);
      if (written > 0 && inactive_pos + written < sizeof(inactive_circs)) {
        inactive_pos += written;
      }
    }
  } SMARTLIST_FOREACH_END(it);
  
  // Remove trailing comma if exists
  if (active_pos > 0 && active_circs[active_pos-1] == ',') {
    active_circs[active_pos-1] = '\0';
  }
  if (inactive_pos > 0 && inactive_circs[inactive_pos-1] == ',') {
    inactive_circs[inactive_pos-1] = '\0';
  }
  
  EWFD_TEMP_LOG("%s cmux-id[%d] active[%u]:[%s] inactive[%u]:[%s]", 
    context, pol->idx, smartlist_len(pol->active_circuit_pqueue), active_circs,
    smartlist_len(pol->inactive_circuit_pqueue), inactive_circs);
#endif
}

/*
* queue从gap状态恢复，如果没有包，就需要发送dummy包
*/
static void ewfd_cmux_revoke_inactive_queue(cell_ewfd_delay_t *delay_item, circuit_t *circ, ewfd_policy_data_t *pol, channel_t *chan) 
{
  // if (delay_item->delay_state != EWFD_MODE_BURST) {
  //   return;
  // }
  if (delay_item->remain_real_pkt == 0) {
    ewfd_send_dummy_packet(circ, delay_item);
  } else {
    ewfd_add_to_active_queue(pol, delay_item);
    scheduler_channel_has_waiting_cells(chan);
  }
}



static void ewfd_send_dummy_packet(circuit_t *circ, cell_ewfd_delay_t *delay_item) {
  EWFD_TEMP_LOG("[delay-event] step:send_dummy_packet circ:%d dummy:%u", 
    ewfd_get_circuit_id(circ), delay_item->send_dummy_pkt);
  ewfd_paddding_op_dummy_impl(circ);
  delay_item->send_dummy_pkt++;
}