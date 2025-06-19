#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_foreach.h"
#include "lib/time/compat_time.h"
#include "core/or/or.h"
#include "core/or/circuitlist.h"
#include <sys/types.h>

#define CIRCUITMUX_PRIVATE
#include "core/or/circuitmux.h"

#include "core/or/circuit_st.h"
#include "core/or/channel.h"
#include "core/or/or_circuit_st.h"
#include <stdint.h>

#define CIRCUITMUX_EWFD_PRIVATE
#include "circuitmux_ewfd.h"

#include "feature/ewfd/debug.h"
#include "feature/ewfd/ewfd_op.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include <math.h>

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
static void ewfd_add_to_sleep_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item);
static void ewfd_remove_active_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *item);
static void ewfd_remove_sleep_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *ewfd_item);
static void ewfd_active_one_sleep_item(ewfd_policy_data_t *pol);
static void ewfd_check_need_dummy_cell(circuit_t *circ);

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
  pol->sleep_circuit_pqueue = smartlist_new();

  return TO_CMUX_POL_DATA(pol);
}

static void ewfd_delay_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data) {
  tor_assert(cmux);
  if (!pol_data) return;

  EWFD_LOG("Free policy cmux: %p", cmux);

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  smartlist_free(pol->active_circuit_pqueue);
  smartlist_free(pol->sleep_circuit_pqueue);
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
  pol_circ->cell_ewfd_delay.heap_index = -1;
  pol_circ->cell_ewfd_delay.sleep_hindex = -1;

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

  EWFD_LOG("Free policy circ: %p", circ_data);
  // remove pol from queues
  if (circ_data->cell_ewfd_delay.heap_index != -1) {
    ewfd_remove_active_item(pol, &circ_data->cell_ewfd_delay);
  }
  if (circ_data->cell_ewfd_delay.sleep_hindex != -1) {
    ewfd_remove_sleep_item(pol, &circ_data->cell_ewfd_delay);
  }

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

  EWFD_LOG("active pqueue: %p alen: %d slen: %d burst: %u send: %u", circ,
    smartlist_len(pol->active_circuit_pqueue), smartlist_len(pol->sleep_circuit_pqueue),
    delay_item->burst_send_cnt, delay_item->cur_send_cnt);

  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    ewfd_add_to_active_queue(pol, delay_item);
    return;
  }

  // add current circuit to active_circuit_pqueue heap
  if (delay_item->delay_state == EWFD_MODE_BURST) {
    ewfd_add_to_active_queue(pol, delay_item);
  } else if (delay_item->delay_state == EWFD_MODE_GAP) {
    ewfd_add_to_sleep_queue(pol, delay_item);
  }

  EWFD_LOG("add active item: %d", EWFD_MODE_BURST);
    // ewfd_add_to_active_queue(pol, delay_item);
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
  // if (pol->base_.magic != EWFD_POL_DATA_MAGIC) {
  //   return;
  // }

  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // deattch的时候，不满足条件
  // tor_assert(delay_item->burst_send_cnt == delay_item->cur_send_cnt);

  EWFD_LOG("inactive: %p alen: %d slen: %d burst: %u send: %u", circ,
    smartlist_len(pol->active_circuit_pqueue), smartlist_len(pol->sleep_circuit_pqueue), 
    delay_item->burst_send_cnt, delay_item->cur_send_cnt);
  
  // remove from queues
  if (delay_item->heap_index != -1) {
    ewfd_remove_active_item(pol, delay_item);
  }
  if (delay_item->sleep_hindex != -1) {
    ewfd_remove_sleep_item(pol, delay_item);
  }
}

/*
* TODO: 当两种算法都启用时就包含delay包，因此需要将delay也改成基于poll的？
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

  // is free
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  if (pol->base_.magic != EWFD_POL_DATA_MAGIC) {
    return;
  }

  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 更新包数量：由queue中包的数量来自动更新
  delay_item->remain_real_pkt = n_cells;

  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    return;
  }

  EWFD_LOG("Set Remain Real Packet: %u circ: %p circ_data: %p\n", delay_item->remain_real_pkt, circ, circ_data);
  if (delay_item->heap_index != -1) {
    if (delay_item->remain_real_pkt == 0) {
      ewfd_add_to_sleep_queue(pol, delay_item);
    } else {
      ewfd_add_to_active_queue(pol, delay_item);
    }
  }
}

// n_cells: 发送的包数量（dummy + real, 优先发real）
/**
 * 需要考虑普通模式，没有BURST/GAP
 * 发送完，就sleep队列。需要set burst去唤醒，或者sleep太久，且有包就唤醒
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

  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);
  cell_ewfd_delay_t *delay_item = &circ_data->cell_ewfd_delay;

  // 更新包数量
  delay_item->cur_send_cnt += n_cells;
  // NORMAL mode不需要管delay  
  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    return;
  }

  EWFD_LOG("xmit cell: %u burst: %u cur: %u", n_cells, delay_item->burst_send_cnt, delay_item->cur_send_cnt);

  // 当前burst发送完毕，进入gap状态
  if (delay_item->cur_send_cnt >= delay_item->burst_send_cnt) {
    EWFD_LOG("Deactive Circ %d", circ->n_circ_id);
    delay_item->delay_state = EWFD_MODE_GAP;
    delay_item->burst_finish_ti = monotime_absolute_msec();
    delay_item->burst_send_cnt = 0;
    delay_item->cur_send_cnt = 0;
    ewfd_add_to_sleep_queue(pol, delay_item);
  } else {
    // still in burst, re-add to update position
    delay_item->delay_state = EWFD_MODE_BURST;
    cell_ewfd_delay_t *first = smartlist_get(pol->active_circuit_pqueue, 0);
    tor_assert(first == delay_item);
    ewfd_add_to_active_queue(pol, delay_item);
  }
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

  /*
  * 从sleep queue唤醒一个 delay_item
  */
  ewfd_active_one_sleep_item(pol);

  // DEAD_CIRCUIT_MAGIC, pick的已经free (circuit_free_)
  if (smartlist_len(pol->active_circuit_pqueue) > 0) {
    cell_ewfd_delay_t *delay_item = smartlist_get(pol->active_circuit_pqueue, 0);
    ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(delay_item, ewfd_policy_circ_data_t, cell_ewfd_delay);
    tor_assert(circ_data);

    EWFD_LOG("pick active circ: %p q-len: %d", circ_data->circ, smartlist_len(pol->active_circuit_pqueue));
    circ = circ_data->circ;

    /* 当real packet数量不足时，往队列加dummy包
    */
    if (circ) {
      if (delay_item->delay_state == EWFD_MODE_BURST) {
        ewfd_check_need_dummy_cell(circ);
      }
    }
  }

  EWFD_LOG("Empty circ----------------------------");
  return circ;
}

// 同时只能在一个对列，先检查是否存在
static void ewfd_add_to_active_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item) {
  if (item->heap_index != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, heap_index), item);
  }
  if (item->sleep_hindex != -1) {
    smartlist_pqueue_remove(pol->sleep_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, sleep_hindex), item);
  }
  smartlist_pqueue_add(pol->active_circuit_pqueue, compare_cell_ewfd_active_circ,
    offsetof(cell_ewfd_delay_t, heap_index), item);
}

// 同时只能在一个对列，先检查是否存在
static void ewfd_add_to_sleep_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item) {
  if (item->heap_index != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, heap_index), item);
  }
  if (item->sleep_hindex != -1) {
    smartlist_pqueue_remove(pol->sleep_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, sleep_hindex), item);
  }
  smartlist_pqueue_add(pol->sleep_circuit_pqueue, compare_cell_ewfd_sleep_circ,
    offsetof(cell_ewfd_delay_t, sleep_hindex), item);
}

static void ewfd_remove_active_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *ewfd_item) {
    tor_assert(pol);
    tor_assert(pol->active_circuit_pqueue);
    tor_assert(ewfd_item);
    tor_assert(ewfd_item->heap_index != -1);
    smartlist_pqueue_remove(pol->active_circuit_pqueue,
                        compare_cell_ewfd_active_circ,
                        offsetof(cell_ewfd_delay_t, heap_index),
                        ewfd_item);
}

static void ewfd_remove_sleep_item(ewfd_policy_data_t *pol, cell_ewfd_delay_t *ewfd_item) {
  tor_assert(pol);
  tor_assert(pol->active_circuit_pqueue);
  tor_assert(ewfd_item);
  tor_assert(ewfd_item->sleep_hindex != -1);
  smartlist_pqueue_remove(pol->sleep_circuit_pqueue,
                      compare_cell_ewfd_active_circ,
                      offsetof(cell_ewfd_delay_t, sleep_hindex),
                      ewfd_item);
}

/* 需要考虑没有设置burst，那么cur_send_cnt会一直增加  
* 1. 先发送burst ti最接近的
* 2. 再先发送包少的对列（早点发完）
* cur_send_pkt, burst_send_cnt, 先发left最少的
*/
static int compare_cell_ewfd_active_circ(const void *p1, const void *p2) {
  const cell_ewfd_delay_t *a = p1, *b = p2;

  // 普通模式，先发包少的队列
  if (a->delay_state == EWFD_MODE_NORMAL || b->delay_state == EWFD_MODE_NORMAL) {
    if (a->remain_real_pkt > b->remain_real_pkt) {
      return -1;
    }
    return 1;
  }

  // burst mode
  tor_assert(a->delay_state == EWFD_MODE_BURST && b->delay_state == EWFD_MODE_BURST);
  tor_assert(a->burst_send_cnt >= a->cur_send_cnt);
  tor_assert(b->burst_send_cnt >= b->cur_send_cnt);

  uint32_t a_remain = a->burst_send_cnt - a->cur_send_cnt;
  uint32_t b_remain = b->burst_send_cnt - b->cur_send_cnt;
  // EWFD_LOG("cur: %u burst: %u", a->cur_send_cnt, a->burst_send_cnt);

  if (a_remain < b_remain) {
    return 1;
  } else if (a_remain > b_remain) {
    return -1;
  }
  return 0;
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

static void ewfd_active_one_sleep_item(ewfd_policy_data_t *pol) {
  uint64_t cur_ti = monotime_absolute_msec();
  cell_ewfd_delay_t * sleep_item = NULL;

  // foreach smartlist
  SMARTLIST_FOREACH_BEGIN(pol->sleep_circuit_pqueue, cell_ewfd_delay_t *, it) {
    uint64_t gap_finish_ti = it->burst_finish_ti + it->gap_ti;
    if (gap_finish_ti > cur_ti) {
      break;
    }

    // 有新包需要发送
    if (it->delay_state == EWFD_MODE_WAIT_TO_BURST) {
      sleep_item = it;
      break;
    }
  } SMARTLIST_FOREACH_END(it);

  // find one
  if (sleep_item != NULL) {
    ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(sleep_item, ewfd_policy_circ_data_t, cell_ewfd_delay);
    tor_assert(circ_data->base_.magic == EWFD_POL_CIRC_DATA_MAGIC);
    sleep_item->delay_state = EWFD_MODE_BURST;
    ewfd_add_to_active_queue(pol, sleep_item);
  }
}

/* API 语义： 发送完pkt_num个包，gap一段时间。
*/
bool circuitmux_set_advance_delay(circuit_t *circ, uint64_t gap_ti_ms, uint32_t pkt_num) {
  channel_t *chan = NULL;

  EWFD_LOG("circuitmux_set_advance_delay: %lu %u", gap_ti_ms, pkt_num);
  return false;

  if (circ->magic == OR_CIRCUIT_MAGIC) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    chan = or_circ->p_chan;
  } else {
    chan = circ->n_chan;
  }

  tor_assert(chan);

  circuitmux_t *cmux = chan->cmux;
  circuitmux_policy_circ_data_t* circ_policy = circuitmux_find_circ_policy(cmux, circ);
  tor_assert(circ_policy);

  /*
  * 前面增加Dummy包的防御，Dummy包也被认为是真实包，目前没法区分队列上真实包究竟有多少
  */
  ewfd_policy_circ_data_t *ewfd_policy_data = TO_EWFD_POL_CIRC_DATA(circ_policy);
  cell_ewfd_delay_t *delay_item = &ewfd_policy_data->cell_ewfd_delay;

  /* 第一次不gap,直接发送
  */
  if (delay_item->delay_state == EWFD_MODE_NORMAL) {
    delay_item->delay_state = EWFD_MODE_BURST;
    delay_item->cur_send_cnt = 0;
    delay_item->burst_finish_ti = 0;
    delay_item->burst_send_cnt = pkt_num;
    return false;
  }

  EWFD_LOG("Want to add delay: %lu %u", delay_item->gap_ti, delay_item->burst_send_cnt);
  // 上次的是否发送完？如果没发完就继续等
  if (delay_item->delay_state != EWFD_MODE_GAP) {
    // should wait
    return true;
  }
  // 不在active queue
  tor_assert(delay_item->heap_index == -1);
  tor_assert(delay_item->burst_send_cnt == 0 && delay_item->cur_send_cnt == 0);

  EWFD_LOG("burst send: %u cur_send: %u remain: %u", delay_item->burst_send_cnt,
     delay_item->cur_send_cnt, delay_item->remain_real_pkt);

  delay_item->delay_state = EWFD_MODE_WAIT_TO_BURST;
  delay_item->gap_ti = gap_ti_ms;
  delay_item->burst_send_cnt = pkt_num;
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(cmux->policy_data);
  ewfd_add_to_sleep_queue(pol, delay_item);

  return false;
}

/* 只有Burst模型实用
* 如果发送队列里没有真实包，就增加一个dummy包
*/
static void ewfd_check_need_dummy_cell(circuit_t *circ) {
  cell_queue_t *queue = NULL;
  if (circ->magic == OR_CIRCUIT_MAGIC) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    queue = &or_circ->p_chan_cells;
  } else {
    queue = &circ->n_chan_cells;
  }

  // need to feed dummy cell
  if (queue->n == 0) {
    EWFD_LOG("ADD a dummy pakcet to: %p", circ);
    packed_cell_t *dummy_cell = ewfd_craft_dummy_packet(circ);
    TOR_SIMPLEQ_INSERT_TAIL(&queue->head, dummy_cell, next);
    queue->n++;
  }
}
