/**
 * @author fripSide 2022, Oct
 * @file ewfd_utils.h
 * @brief utils for log, debug, helpers functions
 **/

#ifndef EWFD_UTILS_H_
#define EWFD_UTILS_H_

// https://stackoverflow.com/questions/996786/how-to-use-the-gcc-attribute-format
void ewfd_log(const char *fmt, ...) __attribute__ ((format (printf, 1, 0)));

#endif