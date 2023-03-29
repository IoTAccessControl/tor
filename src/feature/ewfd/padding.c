#include "feature/ewfd/padding.h"
#include "feature/ewfd/debug.h"
#include <stdint.h>
#include <stdbool.h>
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "core/or/circuitpadding.h"


smartlist_t *client_units = NULL;

static bool check_ewfd_padding_enable(ewfd_padding_conf_st *conf) {

	return true;
}


void ewfd_padding_init() {
	EWFD_LOG("ewfd_padding_init");
	client_units = smartlist_new();
}

void ewfd_padding_free() {
	EWFD_LOG("ewfd_padding_free");
}

// add to origin_circuit
int add_ewfd_units_to_circ(circuit_t *circ) {
	if (!CIRCUIT_IS_ORIGIN(circ)) {
		return 0;
	}
	origin_circuit_t *on_circ = TO_ORIGIN_CIRCUIT(circ);
	if (on_circ->padding_negotiation_failed) {
		return 0;
	}

	// check and add ewfd units to a circit
	uint8_t unit_idx = 0;
	uint8_t target_hopnum = 1;

	// 初始化所有的padding machine
	for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
	}

	if (circpad_negotiate_padding(on_circ, unit_idx,
		target_hopnum,
		CIRCPAD_COMMAND_START,
		circ->padding_machine_ctr) < 0) {
		on_circ->padding_negotiation_failed = 1;
	}

	return 0;
}

int remove_ewfd_units_on_circ(circuit_t *circ) {

}


int trigger_ewfd_units_on_circ(circuit_t *circ) {

}