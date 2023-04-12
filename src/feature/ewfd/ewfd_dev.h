#ifndef EWFD_DEV_H_
#define EWFD_DEV_H_

/*
开发调试阶段
在这里实现几种默认的padding算法
*/

#include "core/or/or.h"
#include "feature/ewfd/circuit_padding.h"
#include <stdint.h>

/** 用C实现的demo seletor算法和padding算法
 * 用于调试和测试
*/

uint64_t ewfd_default_seletor_unit(ewfd_circ_status_st *ewfd_status);

//
uint64_t ewfd_default_init_unit(void);
uint64_t ewfd_default_padding_unit(ewfd_circ_status_st *ewfd_status);


#endif // EWFD_DEV_H_
