#define CIRCUITMUX_EWFD_PRIVATE

#include "circuitmux_ewfd.h"

/*** Static declarations for circuitmux_ewma.c ***/

// static void add_cell_ewma(ewma_policy_data_t *pol, cell_ewma_t *ewma);
// static int compare_cell_ewma_counts(const void *p1, const void *p2);
// static circuit_t * cell_ewma_to_circuit(cell_ewma_t *ewma);
// static inline double get_scale_factor(unsigned from_tick, unsigned to_tick);
// static cell_ewma_t * pop_first_cell_ewma(ewma_policy_data_t *pol);
// static void remove_cell_ewma(ewma_policy_data_t *pol, cell_ewma_t *ewma);
// static void scale_single_cell_ewma(cell_ewma_t *ewma, unsigned cur_tick);
// static void scale_active_circuits(ewma_policy_data_t *pol,
//                                   unsigned cur_tick);

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


/** Adjust the global cell scale factor based on <b>options</b> */
void cmux_ewfd_set_options(const or_options_t *options, const networkstatus_t *consensus) {
	
}


void circuitmux_ewfd_free_all(void) {

}

static circuitmux_policy_data_t *
ewma_alloc_cmux_data(circuitmux_t *cmux) {
	return NULL;
}

static void
ewma_free_cmux_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data) {
	
}
