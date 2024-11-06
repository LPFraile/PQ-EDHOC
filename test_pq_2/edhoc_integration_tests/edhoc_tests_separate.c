/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/kernel.h>

#include <edhoc.h>
#include "txrx_wrapper.h"
#if (defined (USE_TEST_INITIATOR) || defined (USE_TEST_RESPONDER))
 #include "edhoc_test_vectors_p256_v16.h"
#endif
#define TEST_NUM 2
#define PRIORITY 7
#define STACKSIZE_I 50000
#ifdef USE_TEST_INITIATOR
K_THREAD_STACK_DEFINE(thread_initiator_stack_area, STACKSIZE_I);
static struct k_thread thread_initiator_data;
#endif
/*Define for testing external trigger*/
#ifdef POWER_MEASUREMENTS
	#include <zephyr/drivers/gpio.h>
	#define LED0_NODE DT_ALIAS(led0)
	static const struct gpio_dt_spec led_i = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
#endif

#ifdef USE_INTE_NUM
#define INTERACTION_NUM USE_INTE_NUM
#else
#define INTERACTION_NUM 1
#endif
volatile uint64_t times2 = INTERACTION_NUM;

volatile uint8_t msg_cnt = 1;

#ifdef POWER_MEASUREMENTS   
void configure_triggers2(){
	int ret;

	if (!gpio_is_ready_dt(&led_i)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led_i, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}

	gpio_pin_set_dt(&led_i, 1);	
}
#endif
#if (defined (USE_TEST_INITIATOR) || defined (USE_TEST_RESPONDER))

enum err tx_fkt(void *sock, struct byte_array *data)
{
	switch (msg_cnt) {
	case 1:
		zassert_mem_equal__(data->ptr,(uint8_t *)test_vectors[TEST_NUM-1].message_1, data->len,
				    "wrong message1");
		zassert_equal(data->len, test_vectors[TEST_NUM-1].message_1_len ,
			      "wrong message1 length");
		break;
	case 2:
		zassert_mem_equal__(data->ptr, (uint8_t *)test_vectors[TEST_NUM-1].message_2, data->len,
				    "wrong message2");
		zassert_equal(data->len, test_vectors[TEST_NUM-1].message_2_len ,
			      "wrong message1 length");
		break;
	case 3:
		zassert_mem_equal__(data->ptr, (uint8_t *)test_vectors[TEST_NUM-1].message_3, data->len,
				    "wrong message3");
		zassert_equal(data->len, test_vectors[TEST_NUM-1].message_3_len ,
			      "wrong message1 length");
		break;
	case 4:
		zassert_mem_equal__(data->ptr,(uint8_t *)test_vectors[TEST_NUM-1].message_4, data->len,
				    "wrong message4");
		zassert_equal(data->len, test_vectors[TEST_NUM-1].message_4_len,
			      "wrong message1 length");
		break;

	default:
		break;
	}

	msg_cnt++;
	return ok;
}

enum err rx_fkt(void *sock, struct byte_array *data)
{
	switch (msg_cnt) {
	case 1:

		TRY(_memcpy_s(data->ptr, data->len, (uint8_t *)test_vectors[TEST_NUM-1].message_1,
			      test_vectors[TEST_NUM-1].message_1_len));
		data->len =test_vectors[TEST_NUM-1].message_1_len;
		break;
	case 2:
		TRY(_memcpy_s(data->ptr, data->len, (uint8_t *)test_vectors[TEST_NUM-1].message_2,
			      test_vectors[TEST_NUM-1].message_2_len));
		data->len = test_vectors[TEST_NUM-1].message_2_len;
		break;
	case 3:
		TRY(_memcpy_s(data->ptr, data->len,(uint8_t *)test_vectors[TEST_NUM-1].message_3,
			      test_vectors[TEST_NUM-1].message_3_len));
		data->len = test_vectors[TEST_NUM-1].message_3_len;
		break;
	case 4:
		TRY(_memcpy_s(data->ptr, data->len, (uint8_t *)test_vectors[TEST_NUM-1].message_4,
			      test_vectors[TEST_NUM-1].message_4_len));
		data->len = test_vectors[TEST_NUM-1].message_4_len;
		break;

	default:
		break;
	}

	msg_cnt++;
	return ok;
}

enum err ead_fkt(void *params, struct byte_array *ead13)
{
	return ok;
}
void thread_initiator(void *vec_num, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	//PRINT_MSG("Initiator thread started!\n");
	int vec_num_i = *((int *)vec_num) - 1;
	
	enum err r;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t I_PRK_out_buf[32];
	struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
					.len = sizeof(I_PRK_out_buf) };

	uint8_t I_err_msg_buf[0];
	struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
					.len = sizeof(I_err_msg_buf) };

	c_i.sock = NULL;
	c_i.c_i.len = test_vectors[TEST_NUM-1].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[TEST_NUM-1].c_i;
	c_i.method = (enum method_type) * test_vectors[TEST_NUM-1].method;
	c_i.suites_i.len = test_vectors[TEST_NUM-1].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[TEST_NUM-1].SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
    c_i.id_cred_i.len = test_vectors[TEST_NUM-1].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[TEST_NUM-1].id_cred_i;
	c_i.cred_i.len = test_vectors[TEST_NUM-1].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[TEST_NUM-1].cred_i;
	c_i.g_x.len = test_vectors[TEST_NUM-1].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[TEST_NUM-1].g_x_raw;
	c_i.x.len = test_vectors[TEST_NUM-1].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[TEST_NUM-1].x_raw;
	c_i.g_i.len = 0;
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;
	c_i.i.ptr = NULL;
	c_i.sk_i.len = test_vectors[TEST_NUM-1].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[TEST_NUM-1].sk_i_raw;
	c_i.pk_i.len = test_vectors[TEST_NUM-1].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[TEST_NUM-1].pk_i_raw;


	cred_r.id_cred.len = test_vectors[TEST_NUM-1].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[TEST_NUM-1].id_cred_r;
	cred_r.cred.len = test_vectors[TEST_NUM-1].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[TEST_NUM-1].cred_r;
	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.pk.len = test_vectors[TEST_NUM-1].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[TEST_NUM-1].pk_r_raw;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
    #ifdef POWER_MEASUREMENTS
	PRINTF("Start Initiator\n");
	gpio_pin_set_dt(&led_i, 0);
	#endif

	//while(times2>0){	
	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);
  //   times2--;
//	}
	#ifdef POWER_MEASUREMENTS
	PRINTF("Stopt Initiator\n");
	gpio_pin_set_dt(&led_i, 1);
	#endif
	/*zassert_mem_equal__(I_PRK_out.ptr, T1_RFC9529__PRK_out, I_PRK_out.len,
			    "wrong PRK_out");*/

	msg_cnt = 1;
}

void test_edhoc_responder(void)
{
	configure_triggers2();
	enum err r;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t R_PRK_out_buf[32];
	struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
					.len = sizeof(R_PRK_out_buf) };

	uint8_t R_err_msg_buf[0];
	struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
					.len = sizeof(R_err_msg_buf) };

	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)test_vectors[TEST_NUM-1].c_r;
	c_r.c_r.len = test_vectors[TEST_NUM-1].c_r_len;
	c_r.suites_r.len = test_vectors[TEST_NUM-1].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[TEST_NUM-1].SUITES_R;
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;
    c_r.id_cred_r.len = test_vectors[TEST_NUM-1].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[TEST_NUM-1].id_cred_r;
	c_r.cred_r.len = test_vectors[TEST_NUM-1].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[TEST_NUM-1].cred_r;
	c_r.g_y.len = test_vectors[TEST_NUM-1].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[TEST_NUM-1].g_y_raw;
	c_r.y.len = test_vectors[TEST_NUM-1].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[TEST_NUM-1].y_raw;
	c_r.g_r.len = 0;
	c_r.g_r.ptr = NULL;
	c_r.r.len = 0;
	c_r.r.ptr = NULL;
    c_r.sk_r.len = test_vectors[TEST_NUM-1].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[TEST_NUM-1].sk_r_raw;
	c_r.pk_r.len = test_vectors[TEST_NUM-1].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[TEST_NUM-1].pk_r_raw;
 

	cred_i.id_cred.len = test_vectors[TEST_NUM-1].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[TEST_NUM-1].id_cred_i;
	cred_i.cred.len = test_vectors[TEST_NUM-1].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[TEST_NUM-1].cred_i;
	cred_i.g.len = 0;
	cred_i.g.ptr = NULL;
    cred_i.pk.len = test_vectors[TEST_NUM-1].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[TEST_NUM-1].pk_i_raw;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	#ifdef POWER_MEASUREMENTS
	PRINTF("Start Responder\n");
	gpio_pin_set_dt(&led_i, 0);
	#endif 
	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);


	#ifdef POWER_MEASUREMENTS
	PRINTF("Stop Responder\n");
	gpio_pin_set_dt(&led_i, 1);
	#endif 
	/*zassert_mem_equal__(R_PRK_out.ptr, T1_RFC9529__PRK_out, R_PRK_out.len,
			    "wrong PRK_out");*/

	msg_cnt= 1;
}
#endif
void test_edhoc_initiator_alone(void)
{
	#ifdef USE_TEST_INITIATOR
	msg_cnt= 1;
	int vec_num = 2;
	configure_triggers2();
	while(times2>0){	
	k_tid_t initiator_tid = k_thread_create(
	&thread_initiator_data, thread_initiator_stack_area,
	K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
	thread_initiator, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
	K_NO_WAIT);

	k_thread_start(&thread_initiator_data);

	if (0 != k_thread_join(&thread_initiator_data, K_FOREVER)) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(initiator_tid);
	}
	times2--;
	}
	#endif
}
void test_edhoc_responder_alone(void)
{
	
}