#ifndef EWFD_TICKER_H_
#define EWFD_TICKER_H_

#include "lib/evloop/timers.h"
#include <stdint.h>

void ewfd_init_ticker(tor_timer_t **ticker, timer_cb_fn_t cb, void *arg);


void ewfd_remove_ticker(tor_timer_t **ticker);

void ewfd_schedule_ticker(tor_timer_t *ticker, uint32_t next_ti_ms);


#endif // EWFD_TICKER_H_
