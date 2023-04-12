#ifndef EWFD_HELPER_H_
#define EWFD_HELPER_H_

#include <stdint.h>

/**
注册到eBPF VM的helper函数
*/

int send_dummy_cell(void *ewfd_status, uint32_t delay);
int send_delay_packet(void *ewfd_status, uint32_t delay);

#endif // EWFD_HELPER_H_
