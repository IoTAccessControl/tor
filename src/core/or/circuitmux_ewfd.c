#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_foreach.h"
#include "lib/time/compat_time.h"
#include "core/or/or.h"
#include "core/or/circuitlist.h"

#define CIRCUITMUX_PRIVATE
#include "core/or/circuitmux.h"

#include "core/or/circuit_st.h"
#include "core/or/channel.h"
#include "core/or/or_circuit_st.h"
#include <stdint.h>

#define CIRCUITMUX_EWFD_PRIVATE
#include "circuitmux_ewfd.h"

#include "feature/ewfd/debug.h"
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
  pol_circ->cell_ewfd_delay.delay_state = EWFD_DELAY_BURST;
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
  ewfd_policy_circ_data_t *circ_data = TO_EWFD_POL_CIRC_DATA(pol_circ_data);

  EWFD_LOG("Free policy circ: %p", circ_data);

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

  // add current circuit to active_circuit_pqueue heap
  if (delay_item->delay_state == EWFD_DELAY_BURST) {
   
  } else if (delay_item->delay_state == EWFD_DELAY_GAP) {
    // ewfd_add_to_sleep_queue(pol, delay_item);
  }

   EWFD_LOG("add active item: %d", EWFD_DELAY_BURST);
   ewfd_add_to_active_queue(pol, delay_item);
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

  // deattch的时候，不满足条件
  // tor_assert(delay_item->burst_send_cnt == delay_item->cur_send_cnt);

  EWFD_LOG("inactive: %p alen: %d slen: %d burst: %u send: %u", circ,
    smartlist_len(pol->active_circuit_pqueue), smartlist_len(pol->sleep_circuit_pqueue), 
    delay_item->burst_send_cnt, delay_item->cur_send_cnt);
  
  if (delay_item->delay_state == EWFD_DELAY_BURST) {
    EWFD_LOG("remove active item: %d", EWFD_DELAY_BURST);
    ewfd_remove_active_item(pol, delay_item);
  } else if (delay_item->delay_state == EWFD_DELAY_GAP) {
    // ewfd_remove_sleep_item(pol, delay_item);
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

  EWFD_LOG("Set Remain Real Packet: %u circ: %p circ_data: %p\n", delay_item->remain_real_pkt, circ, circ_data);

  // re-add
  // 更新了真实包数量之后，需要更新位置
  // 这里可能被 free 
  // ewfd_add_to_active_queue(pol, delay_item);
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
  delay_item->cur_send_cnt += n_cells;
  // real packet由set_n_cell更新

  // 当前burst发送完毕，进入gap状态
  if (delay_item->cur_send_cnt == delay_item->burst_send_cnt) {
    EWFD_LOG("Deactive Circ %d", circ->n_circ_id);
    delay_item->delay_state = EWFD_DELAY_GAP;
    delay_item->burst_finish_ti = monotime_absolute_msec();
    delay_item->burst_send_cnt = 0;
    delay_item->cur_send_cnt = 0;
    // ewfd_remove_active_item(pol, delay_item);
    // ewfd_add_to_sleep_queue(pol, delay_item);
  }
  // tmp = smartlist_pqueue_pop(pol, delay_item);
  // tor_assert(tmp == delay_item);
  // add_cell_ewma(pol, cell_ewma);
  cell_ewfd_delay_t *first = smartlist_get(pol->active_circuit_pqueue, 0);
  tor_assert(first == delay_item);
  ewfd_add_to_active_queue(pol, delay_item);
}

/* 返回时间到了发送界限，并且有真实包的对列
*/
static circuit_t * ewfd_delay_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data) {
  tor_assert(cmux);
  tor_assert(pol_data);
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(pol_data);

  /*
  * 唤醒sleep queue里的有效队列，将ti最接近的加入到发送队列(burst)
  * 切换GAP为Burst
  */
  uint64_t cur_ti = monotime_absolute_msec();
  // while (true) {
  //   if (smartlist_len(pol->sleep_circuit_pqueue) <= 0) {
  //     break;
  //   }
  //   cell_ewfd_delay_t *sleep_item = smartlist_pqueue_pop(pol->sleep_circuit_pqueue,
  //                                       compare_cell_ewfd_sleep_circ,
  //                                       offsetof(cell_ewfd_delay_t, sleep_hindex));
  //   if (!sleep_item) {
  //     break;
  //   }
  //   // 没有需要发送的，继续sleep
  //   if (sleep_item->gap_finish_ti > cur_ti) {
  //     break;
  //   }
  //   // 已经发送完，等待更新next_send_ti（发下一个delay命令），移除对列，等待下一个burst加入发送队列
  //   if (sleep_item->burst_send_cnt <= sleep_item->cur_send_cnt) {
  //     continue;
  //   }

  //   // sleep_item->gap_finish_ti <= cur_ti，且有包需要发送
  //   ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(sleep_item, ewfd_policy_circ_data_t, cell_ewfd_delay);
  //   tor_assert(circ_data);

  //   // 判断是否被回收 
  //   if (circ_data->base_.magic == EWFD_POL_CIRC_DATA_MAGIC) {
  //     sleep_item->delay_state = EWFD_DELAY_BURST;

  //     EWFD_LOG("move from sleep queue to active queue: %p", sleep_item);
  //     // ewfd_add_to_active_queue(pol, sleep_item);
  //   }
  // }

  // DEAD_CIRCUIT_MAGIC, pick的已经free (circuit_free_)
  if (smartlist_len(pol->active_circuit_pqueue) > 0) {
    cell_ewfd_delay_t *delay_item = smartlist_get(pol->active_circuit_pqueue, 0);
    ewfd_policy_circ_data_t *circ_data = SUBTYPE_P(delay_item, ewfd_policy_circ_data_t, cell_ewfd_delay);
    tor_assert(circ_data);

    EWFD_LOG("pick active circ: %p q-len: %d", circ_data->circ, smartlist_len(pol->active_circuit_pqueue));
    return circ_data->circ;
  }

  EWFD_LOG("Empty circ----------------------------");
  return NULL;
}

/*
* 1. 先发送burst ti最接近的
* 2. 再先发送包少的对列（早点发完）
*/
static int compare_cell_ewfd_active_circ(const void *p1, const void *p2) {
  const cell_ewfd_delay_t *a = p1, *b = p2;
  if (a->remain_real_pkt > b->remain_real_pkt) {
    return -1;
  } else if (a->remain_real_pkt < b->remain_real_pkt) {
    return 1;
  }
  return 0;
}

// 先检查是否存在
static void ewfd_add_to_active_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *item) {
  if (item->heap_index != -1) {
    smartlist_pqueue_remove(pol->active_circuit_pqueue,
                        compare_cell_ewfd_active_circ,
                        offsetof(cell_ewfd_delay_t, heap_index),
                        item);
  }
  smartlist_pqueue_add(pol->active_circuit_pqueue, compare_cell_ewfd_active_circ,
    offsetof(cell_ewfd_delay_t, heap_index), item);
}

// 先检查是否存在
static void ewfd_add_to_sleep_queue(ewfd_policy_data_t* pol, cell_ewfd_delay_t *cell) {
  if (cell->sleep_hindex != -1) {
    smartlist_pqueue_remove(pol->sleep_circuit_pqueue, compare_cell_ewfd_sleep_circ,
      offsetof(cell_ewfd_delay_t, sleep_hindex), cell);
  }
  smartlist_pqueue_add(pol->sleep_circuit_pqueue, compare_cell_ewfd_sleep_circ,
    offsetof(cell_ewfd_delay_t, sleep_hindex), cell);
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

/*
*  1. 发送时间更接近的
*/
static int compare_cell_ewfd_sleep_circ(const void *p1, const void *p2) {
  const cell_ewfd_delay_t *a = p1, *b = p2;
  if (a->gap_finish_ti < b->gap_finish_ti) {
    return 1;
  } else if (a->gap_finish_ti > b->gap_finish_ti) {
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

/* circuit必须处于Gap状态
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
  EWFD_LOG("Want to add delay: %lu %u", delay_item->gap_finish_ti, delay_item->burst_send_cnt);
  // 上次的是否发送完？如果没发完就继续等
  if (delay_item->delay_state != EWFD_DELAY_GAP) {
    // should wait
    return true;
  }
  // 不在active queue
  tor_assert(delay_item->heap_index == -1);
  tor_assert(delay_item->burst_send_cnt == 0 && delay_item->cur_send_cnt == 0);

  EWFD_LOG("burst send: %u cur_send: %u remain: %u", delay_item->burst_send_cnt,
     delay_item->cur_send_cnt, delay_item->remain_real_pkt);

  delay_item->gap_finish_ti = delay_item->burst_finish_ti + gap_ti_ms;
  delay_item->burst_send_cnt = pkt_num;
  ewfd_policy_data_t *pol = TO_EWFD_POL_DATA(cmux->policy_data);
  ewfd_add_to_sleep_queue(pol, delay_item);

  return false;
}
