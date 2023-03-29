#include "feature/ewfd/debug.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "core/or/or.h"
#include "core/or/extend_info_st.h"
#include "core/or/extendinfo.h"
#include "feature/nodelist/nodelist.h"
#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/channel.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/string/printf.h"
#include "app/config/config.h"


void ewfd_my_log_caller(const char *fn, const char *fi, int li, const char *format, ...) {
	char my_log[128] = {0};
	
	va_list args;
	va_start(args, format);
	vsprintf(my_log, format, args);
	va_end(args);
	log_fn_(LOG_LAST_LEV, LD_GENERAL, __FUNCTION__, "%-100s -> %s:%d(%s)", my_log, fi, li, fn);
}

#ifdef EWFD_DEBUG
char ewfd_circuit_log[128];

/**
Dump peer node info for the cirucit of sending/recve a cell

Notes: 
- use nickname to distinguish different node
- some or_circuit_t's nickname cannot be obtained as they do not finishing handshake
*/
const char *ewfd_get_circuit_info(circuit_t *circ) {
	tor_assert(circ);
	char *self = get_options()->Nickname;
	const char *node_name = "unkown";
	// char *kh = "";
	uint32_t peer_circ_id = 0;
	
	if (CIRCUIT_IS_ORIGIN(circ)) {
		origin_circuit_t *oric = TO_ORIGIN_CIRCUIT(circ);
		tor_assert(oric->cpath);
		node_name = oric->cpath->extend_info->nickname;
		peer_circ_id = circ->n_circ_id;
		// kh = oric->cpath->rend_circ_nonce;
	} else {
		or_circuit_t *oric = TO_OR_CIRCUIT(circ);
		
		if (oric->p_hop == NULL) {
			const node_t *node = node_get_by_id(oric->p_chan->identity_digest);
			if (node) {
				extend_info_t *info = extend_info_from_node(node, 1, false);
				if (info) {
					TO_OR_CIRCUIT(circ)->p_hop = extend_info_dup(info);
				}
			}
		}

		if (oric->p_hop != NULL) {
			node_name = oric->p_hop->nickname;
		} 
		peer_circ_id = oric->p_circ_id;
		// kh = oric->rend_circ_nonce;
	}

	tor_snprintf(ewfd_circuit_log, 64, "self:%s peer:[%s](%u)", self, node_name, peer_circ_id);
	return ewfd_circuit_log;
}

#else

const char *ewfd_get_circuit_info(circuit_t *circ) {
	return "";
}

#endif