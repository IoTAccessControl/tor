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

const char *show_relay_command(uint8_t command) {
	static char buf[64];
	switch (command) {
	case RELAY_COMMAND_BEGIN: return "BEGIN";
	case RELAY_COMMAND_DATA: return "DATA";
	case RELAY_COMMAND_END: return "END";
	case RELAY_COMMAND_CONNECTED: return "CONNECTED";
	case RELAY_COMMAND_SENDME: return "SENDME";
	case RELAY_COMMAND_EXTEND: return "EXTEND";
	case RELAY_COMMAND_EXTENDED: return "EXTENDED";
	case RELAY_COMMAND_TRUNCATE: return "TRUNCATE";
	case RELAY_COMMAND_TRUNCATED: return "TRUNCATED";
	case RELAY_COMMAND_DROP: return "DROP";
	case RELAY_COMMAND_RESOLVE: return "RESOLVE";
	case RELAY_COMMAND_RESOLVED: return "RESOLVED";
	case RELAY_COMMAND_BEGIN_DIR: return "BEGIN_DIR";
	case RELAY_COMMAND_ESTABLISH_INTRO: return "ESTABLISH_INTRO";
	case RELAY_COMMAND_ESTABLISH_RENDEZVOUS: return "ESTABLISH_RENDEZVOUS";
	case RELAY_COMMAND_INTRODUCE1: return "INTRODUCE1";
	case RELAY_COMMAND_INTRODUCE2: return "INTRODUCE2";
	case RELAY_COMMAND_RENDEZVOUS1: return "RENDEZVOUS1";
	case RELAY_COMMAND_RENDEZVOUS2: return "RENDEZVOUS2";
	case RELAY_COMMAND_INTRO_ESTABLISHED: return "INTRO_ESTABLISHED";
	case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
		return "RENDEZVOUS_ESTABLISHED";
	case RELAY_COMMAND_INTRODUCE_ACK: return "INTRODUCE_ACK";
	case RELAY_COMMAND_EXTEND2: return "EXTEND2";
	case RELAY_COMMAND_EXTENDED2: return "EXTENDED2";
	case RELAY_COMMAND_PADDING_NEGOTIATE: return "PADDING_NEGOTIATE";
	case RELAY_COMMAND_PADDING_NEGOTIATED: return "PADDING_NEGOTIATED";
	default:
		tor_snprintf(buf, sizeof(buf), "Unrecognized relay command %u",
					(unsigned)command);
		return buf;
	}
}

#ifdef USE_EWFD_STATISTICS
/* 在client端统计padding效果  
*/
void ewfd_statistic_on_cell_event(circuit_t *circ, bool is_send, uint8_t command) {
	bool is_edge = CIRCUIT_IS_ORIGIN(circ);
	if (is_send) {
		
	} else { // receive
		if (is_edge && (command == RELAY_COMMAND_BEGIN 
			|| command == RELAY_COMMAND_DATA
			|| command == RELAY_COMMAND_END
			|| command == RELAY_COMMAND_DROP
			)) {
			uint32_t gid = TO_ORIGIN_CIRCUIT(circ)->global_identifier;
			EWFD_STAT_LOG("[STATISTICS] [%u] %s", gid, show_relay_command(command));
		}
	}
}
#else 

void ewfd_statistic_on_cell_event(circuit_t *circ, bool is_send, uint8_t command) {}

#endif // USE_EWFD_STATISTICS

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
	// char *self = get_options()->Nickname;
	const char *next_node = "unkown";
	const char *prev_node = "unkown";
	// char *kh = "";
	uint32_t next_circ_id = 0, prev_circ_id = 0;
	int gid = -1;
	
	if (CIRCUIT_IS_ORIGIN(circ)) {
		origin_circuit_t *oric = TO_ORIGIN_CIRCUIT(circ);
		tor_assert(oric->cpath);
		next_node = oric->cpath->extend_info->nickname;
		// kh = oric->cpath->rend_circ_nonce;
		gid = oric->global_identifier;
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

		if (circ->n_hop != NULL) {
			next_node = circ->n_hop->nickname;
			next_circ_id = circ->n_circ_id;
		}

		if (oric->p_hop != NULL) {
			prev_node = oric->p_hop->nickname;
			prev_circ_id = oric->p_circ_id;
		} 
	}

	if (gid != -1) {
		tor_snprintf(ewfd_circuit_log, 64, "origin-circ: %d next: %s", gid, next_node);
	} else {
		tor_snprintf(ewfd_circuit_log, 64, "or-circ prev: [%s](%u) next: [%s](%u)", prev_node, prev_circ_id, next_node, next_circ_id);
	}
	return ewfd_circuit_log;
}

#else

const char *ewfd_get_circuit_info(circuit_t *circ) {
	return "";
}

#endif



uint32_t ewfd_get_circuit_id(circuit_t *circ) {
	if (CIRCUIT_IS_ORIGIN(circ)) {
		return TO_ORIGIN_CIRCUIT(circ)->global_identifier;
	} else {
		return TO_OR_CIRCUIT(circ)->p_circ_id;
	}
}