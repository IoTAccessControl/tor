
#include "../headers/ewfd.h"
#include <stdint.h>


#define OP_PADDING 1


#define MODE_SLOWDOWN 101
#define MODE_FASTUP 102

#define VAR_INIT_RATE 1
#define VAR_DEPRECIATION_RATIO 2
#define VAR_INCREASE_GRADIENT 3
#define VAR_BUDGET_RATIO 5
#define VAR_LAST_SCHEDULE_PKT 6


#define PADDING_GAP 500
#define TICK_GAP 20


SEC("ewfd/padding/ezlinear/init")
uint64_t ewfd_init(void *ewfd_unit) {
	ewfd_set_var((uint64_t) ewfd_unit, VAR_INIT_RATE, 101);
	ewfd_set_var((uint64_t) ewfd_unit, VAR_DEPRECIATION_RATIO, 1000);
	ewfd_set_var((uint64_t) ewfd_unit, VAR_INCREASE_GRADIENT, 1000);
	ewfd_set_var((uint64_t) ewfd_unit, VAR_BUDGET_RATIO, 1000);
	return 0;
}


/*
last_real=helper_get_past_sent_count()-cell_count
(若上一段时间规划的发送速率超过开销且缓冲区数据较少，则切到slowdown模式否则切到fast模式)
status="slowdown" if last_schedule > (1+budget_ratio)*last_real and send_rate*PADDING_GAP*depreciation_ratio>helper_get_buffer_occupacy() else "fastup"
last_schedule:=0
if status="slowdown":
    send_rate:=min(send_rate*depreciation_ratio,init_rate) 
while tick_last < tick+PADDING_GAP:
    if status="fastup":
        send_rate+=PADDING_GAP*increase_gradient
    num=PADDING_GAP*send_rate
    helper_add_delay(tick_last,num)
    last_schedule+=num
    tick_last+=TICK_GAP
(update status)
cell_count:=helper_get_past_sent_count()

*/

SEC("ewfd/padding/ezlinear/tick")
uint64_t ewfd_tick(struct ewfd_circ_status_t *ewfd_status) {
	uint64_t ret = (uint64_t) OP_PADDING << 32;

	uint64_t ewfd_unit = ewfd_status->ewfd_unit;
	uint8_t status = ewfd_status->defense_status;
	uint32_t budget_ratio = ewfd_load_var(ewfd_unit, VAR_BUDGET_RATIO);
	uint32_t last_schedule_pkt = ewfd_load_var(ewfd_unit, VAR_LAST_SCHEDULE_PKT);
	uint32_t send_rate = ewfd_load_var(ewfd_unit, VAR_INIT_RATE);
	uint32_t depreciation_ratio = ewfd_load_var(ewfd_unit, VAR_DEPRECIATION_RATIO);
	uint32_t increase_gradient = ewfd_load_var(ewfd_unit, VAR_INCREASE_GRADIENT);

	uint32_t now_ti = ewfd_status->now_ti;
	uint32_t send_ti = ewfd_status->last_padding_ti;

	uint32_t last_real_pkt = ewfd_status->send_cell_cnt - ewfd_status->send_dummy_cnt;
	uint32_t last_queue_occupacy = ewfd_status->queue_occupacy;


	// send_rate*PADDING_GAP*depreciation_ratio>helper_get_buffer_occupacy()
	status = MODE_SLOWDOWN;

	if (last_schedule_pkt > (1 + budget_ratio/1000) * last_real_pkt && 
		send_rate * PADDING_GAP * depreciation_ratio > last_queue_occupacy) {
		status = MODE_FASTUP;
	}

	last_schedule_pkt = 0;
	if (status == MODE_SLOWDOWN) {
		send_rate = send_rate * depreciation_ratio / 1000;
	}

	while (send_ti < now_ti + PADDING_GAP) {
		if (status == MODE_FASTUP) {
			send_rate += PADDING_GAP * increase_gradient / 1000;
		}
		uint32_t num = PADDING_GAP * send_rate;
		ewfd_op_delay((void *) ewfd_status->on_circ, send_ti, 0, num);
		last_schedule_pkt += num;
		send_ti += TICK_GAP;
	}

	return ret | last_schedule_pkt;
}