/**
 * @author fripSide 2022, Oct
 * @file ewfd_utils.h
 * @brief utils for log, debug, helpers functions
 **/

#ifndef EWFD_UTILS_H_
#define EWFD_UTILS_H_

#include "core/or/or.h"
#include "feature/ewfd/debug.h"

#define EWFD_NODE_ROLE_CLIENT 0b1
#define EWFD_NODE_ROLE_OR 	  0b10
#define EWFD_NODE_ROLE_EXIT   0b100

int ewfd_get_node_role_for_circ(circuit_t *circ);

#endif