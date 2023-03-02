/**
 * @author fripSide 2022, Oct
 * @file ewfd_utils.h
 * @brief utils for log, debug, helpers functions
 **/

#ifndef EWFD_UTILS_H_
#define EWFD_UTILS_H_


#define EWFD_DEBUG

/* show the full path of caller */ 
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
	#define EWFD_LOG(domain, args...) \
		do {} while(0)
#endif // EWFD_DEBUG

#endif