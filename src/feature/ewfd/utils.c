#include "feature/ewfd/utils.h"
#include "app/config/config.h"
#include "core/or/circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"

int ewfd_get_node_role_for_circ(circuit_t *circ) {
	bool is_client = get_options()->SocksPort_set;
	bool is_origin = CIRCUIT_IS_ORIGIN(circ);
	int roles = 0;
	if (is_origin && is_client) { // client
		roles |= EWFD_NODE_ROLE_CLIENT;
	} else { // Exit
		bool is_exit = get_options()->ExitRelay != 0;
		if (is_exit) {
			roles |= EWFD_NODE_ROLE_EXIT;
		} else { // OR
			roles |= EWFD_NODE_ROLE_OR;
		}
	}
	
	return roles;
}