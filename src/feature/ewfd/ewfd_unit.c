
#include "feature/ewfd/ewfd_unit.h"
#include "feature/ewfd/ewfd_helper.h"
#include "core/or/or.h"

ewfd_unit_st* init_ewfd_unit(void) {
	ewfd_unit_st *unit = (ewfd_unit_st *) tor_malloc_zero(sizeof(ewfd_unit_st));
	return unit;
}

void free_ewfd_unit(ewfd_unit_st *ewfd_unit) {
	tor_free(ewfd_unit);
}