#ifndef EWFD_DEBUG_H_
#define EWFD_DEBUG_H_

#include "core/or/or.h"

#define EWFD_DEBUG // enable debug
// #define USE_EWFD_STATISTICS // enable state logs

/*----------------------------------------------------------------------------
* Debug Log
*/

/* CONFIG: show the full path of caller */ 
// #define SHOW_LOG_FILE_PATH

// https://stackoverflow.com/questions/996786/how-to-use-the-gcc-attribute-format
void ewfd_my_log_caller(const char *fn, const char *fi, int li, const char *format, ...) __attribute__((format(printf, 4, 5)));

// logs for eWFD dev, shown in a seperate file
#ifdef EWFD_DEBUG
	#ifdef SHOW_LOG_FILE_PATH
	#define EWFD_LOG(args...) \
		ewfd_my_log_caller(__FUNCTION__, __FILE__, __LINE__, args)
	#else 
		#define EWFD_LOG(args...) \
			log_fn_(LOG_LAST_LEV, LD_GENERAL, __FUNCTION__, args)
	#endif // SHOW_LOG_FILE_PATH
#else
	#define EWFD_LOG(args...) \
		do {} while(0)
#endif // EWFD_DEBUG

/* 用于python脚本统计padding包
*/
#ifdef USE_EWFD_STATISTICS
	#define EWFD_STAT_LOG(args...) \
		log_fn_(LOG_LAST_LEV, LD_GENERAL, __FUNCTION__, args)
#else
	#define EWFD_STAT_LOG(args...) \
		do {} while(0)
#endif	// USE_EWFD_STATISTICS


/*----------------------------------------------------------------------------
* Get Circuit Info for debug
*/
// extern char ewfd_circuit_log[128];
const char *ewfd_get_circuit_info(circuit_t *circ);

uint32_t ewfd_get_circuit_id(circuit_t *circ);

void ewfd_statistic_on_cell_event(circuit_t *circ, bool is_send, uint8_t command);

const char *show_relay_command(uint8_t command);

#endif
