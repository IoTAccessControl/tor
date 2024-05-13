#ifndef EWFD_CIRCUITMUX_EWFD_H_
#define EWFD_CIRCUITMUX_EWFD_H_

#include "core/or/or.h"
#include "core/or/circuitmux.h"

/* The public EWFD policy callbacks object. */
extern circuitmux_policy_t ewfd_policy;


/* Externally visible eWFD functions */
void cmux_ewfd_set_options(const or_options_t *options,
                           const networkstatus_t *consensus);

void circuitmux_ewfd_free_all(void);

#ifdef CIRCUITMUX_EWFD_PRIVATE

/*** EWFD structures ***/

typedef struct cell_ewfd_t cell_ewfd_t;
typedef struct ewfd_policy_data_t ewfd_policy_data_t;
typedef struct ewfd_policy_circ_data_t ewfd_policy_circ_data_t;

struct cell_ewfd_t {
  /** The last 'tick' at which we recalibrated cell_count.
   *
   * A cell sent at exactly the start of this tick has weight 1.0. Cells sent
   * since the start of this tick have weight greater than 1.0; ones sent
   * earlier have less weight. */
  uint32_t last_adjusted_tick;
  /** The EWMA of the cell count. */
  uint32_t cell_count;
  /** True iff this is the cell count for a circuit's previous
   * channel. */
  uint32_t is_for_p_chan : 1;
  /** The position of the circuit within the OR connection's priority
   * queue. */
  int heap_index;
};


// ewfd_policy_circ_data_t

STATIC void cell_ewfd_initialize_ticks(void);

#endif //CIRCUITMUX_EWFD_PRIVATE

#endif //EWFD_CIRCUITMUX_EWFD_H_
