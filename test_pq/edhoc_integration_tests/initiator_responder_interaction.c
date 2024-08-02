/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/debug/thread_analyzer.h>

#include <edhoc.h>

#include "edhoc_test_vectors_p256_v16.h"
#include "latency.h"
/* scheduling priority used by each thread */
#define PRIORITY 7

#ifdef USE_SUIT_7
#define TEST_X5T_NUM 7
#define TEST_X5CHAIN_NUM 8
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 40000
#define STACKSIZE_R 30000
#define MAX_MSG_SIZE 3200

#elif USE_SUIT_9
#define TEST_X5T_NUM 9
#define TEST_X5CHAIN_NUM 10
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 50000
#define STACKSIZE_R 40000
#define MAX_MSG_SIZE 3500

#elif USE_SUIT_11
#define TEST_X5T_NUM 14
#define TEST_X5CHAIN_NUM 14
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 100000
#define STACKSIZE_R 40000
#define MAX_MSG_SIZE 2300

#elif USE_SUIT_12
#define TEST_X5T_NUM 11
#define TEST_X5CHAIN_NUM 12
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 90000
#define STACKSIZE_R 90000
#define MAX_MSG_SIZE 7104


#elif USE_SUIT_13
#define TEST_X5T_NUM 15
#define TEST_X5CHAIN_NUM 15
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 120000
#define STACKSIZE_R 80000
#define MAX_MSG_SIZE 7000
#endif
uint8_t I_prk_exporter_buf[32];
struct byte_array I_prk_exporter = { .ptr = I_prk_exporter_buf,
				     .len = sizeof(I_prk_exporter_buf) };

uint8_t I_master_secret_buf[16];
struct byte_array I_master_secret = { .ptr = I_master_secret_buf,
				      .len = sizeof(I_master_secret_buf) };

uint8_t I_master_salt_buf[8];
struct byte_array I_master_salt = { .ptr = I_master_salt_buf,
				    .len = sizeof(I_master_salt_buf) };

uint8_t I_PRK_out_buf[32];
struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
				.len = sizeof(I_PRK_out_buf) };

uint8_t I_err_msg_buf[0];
struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
				.len = sizeof(I_err_msg_buf) };
/******************************************************************************/

uint8_t R_prk_exporter_buf[32];
struct byte_array R_prk_exporter = { .ptr = R_prk_exporter_buf,
				     .len = sizeof(R_prk_exporter_buf) };

uint8_t R_master_secret_buf[16];
struct byte_array R_master_secret = { .ptr = R_master_secret_buf,
				      .len = sizeof(R_master_secret_buf) };

uint8_t R_master_salt_buf[8];
struct byte_array R_master_salt = { .ptr = R_master_salt_buf,
				    .len = sizeof(R_master_salt_buf) };

uint8_t R_PRK_out_buf[32];
struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
				.len = sizeof(R_PRK_out_buf) };

uint8_t R_err_msg_buf[0];
struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
				.len = sizeof(R_err_msg_buf) };


K_THREAD_STACK_DEFINE(thread_initiator_stack_area, STACKSIZE_I);
static struct k_thread thread_initiator_data;
K_THREAD_STACK_DEFINE(thread_responder_stack_area, STACKSIZE_R);
static struct k_thread thread_responder_data;

/*semaphores*/
K_SEM_DEFINE(tx_initiator_completed, 0, 1);
K_SEM_DEFINE(tx_responder_completed, 0, 1);

/*message exchange buffer*/
uint8_t msg_exchange_buf[MAX_MSG_SIZE];
uint32_t msg_exchange_buf_len = sizeof(msg_exchange_buf);

void semaphore_give(struct k_sem *sem)
{
	k_sem_give(sem);
}

enum err semaphore_take(struct k_sem *sem, uint8_t *data, uint32_t *data_len)
{
	if (k_sem_take(sem, K_FOREVER) != 0) {
		PRINT_MSG("Cannot receive a message!\n");
	} else {
		if (msg_exchange_buf_len > *data_len) {
			return buffer_to_small;
		} else {
			memcpy(data, msg_exchange_buf, *data_len);
			*data_len = msg_exchange_buf_len;
		}
	}
	return ok;
}

enum err copy_message(uint8_t *data, uint32_t data_len)
{
	if (data_len > sizeof(msg_exchange_buf)) {
		PRINT_MSG("msg_exchange_buf to small\n");
		return buffer_to_small;
	} else {
		memcpy(msg_exchange_buf, data, data_len);
		msg_exchange_buf_len = data_len;
	}
	return ok;
}

enum err tx_initiator(void *sock, struct byte_array *data)
{
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_initiator_completed);
	return ok;
}

enum err tx_responder(void *sock, struct byte_array *data)
{
	//PRINTF("tx_responder data len: %d\n", data->len);
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	//PRINTF("msg_exchange_buf_len: %d\n",msg_exchange_buf_len);
	semaphore_give(&tx_responder_completed);
	return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data)
{
	PRINTF("msg_exchange_buf_len: %d\n", msg_exchange_buf_len);
	return semaphore_take(&tx_responder_completed, data->ptr, &data->len);
}
enum err rx_responder(void *sock, struct byte_array *data)
{
	return semaphore_take(&tx_initiator_completed, data->ptr, &data->len);
}
enum err ead_process(void *params, struct byte_array *ead13)
{
	return ok;
}

/**
 * @brief			A thread in which an Initiator instance is executed
 * 
 * @param vec_num 	Test vector number
 * @param dummy2 	unused
 * @param dummy3 	unused
 */
void thread_initiator(void *vec_num, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	//PRINT_MSG("Initiator thread started!\n");
	int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("Initiator thread started with test vector %d!\n",vec_num_i +1);
	enum err r;

	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	c_i.sock = NULL;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	c_i.ead_1.len = test_vectors[vec_num_i].ead_1_len;
	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	c_i.ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i.g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i.x.len = test_vectors[vec_num_i].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i.g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i.i.len = test_vectors[vec_num_i].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i.sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r.g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
    
   #ifdef GEN_EPH_KEYS
		struct suite suit_in;
		get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
				&suit_in);
				  
		PRINTF("INITIATOR SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

		uint8_t PQ_public_random[get_kem_pk_len(suit_in.edhoc_ecdh)];
		uint8_t PQ_secret_random[get_kem_sk_len(suit_in.edhoc_ecdh)];
		//PRINTF("Arrive here 2\n");
		c_i.g_x.ptr = PQ_public_random;
		//c_i.g_x.len = PQ_public_random.len;
		c_i.g_x.len = get_kem_pk_len(suit_in.edhoc_ecdh);
		//PRINTF("Arrive here 3\n");
		c_i.x.ptr = PQ_secret_random;
		c_i.x.len = get_kem_sk_len(suit_in.edhoc_ecdh);

		ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &c_i.x,&c_i.g_x);
		/*PRINTF("CC len:%d",get_kem_cc_len(suit_in.edhoc_ecdh));
        uint8_t CIPHE[get_kem_cc_len(suit_in.edhoc_ecdh)];
		uint8_t SS[32];
		uint8_t SS2[32];
		struct byte_array cc;
		cc.ptr = CIPHE;
		cc.len = get_kem_cc_len(suit_in.edhoc_ecdh);
		struct byte_array g_xy;
		g_xy.ptr = SS;
		g_xy.len = 32;
		struct byte_array g_xy2;
		g_xy2.ptr = SS;
		g_xy2.len = 32;
		TRY(kem_encapsulate(suit_in.edhoc_ecdh,&c_i.g_x,&cc,&g_xy));
		PRINT_MSG("encapsulate correct\n");
    	PRINT_ARRAY("gxy:",g_xy.ptr,g_xy.len);
		PRINT_ARRAY("cc",cc.ptr,cc.len);*/

		TRY(kem_decapsulate(suit_in.edhoc_ecdh, &cc, &c_i.x, &g_xy2));
	
 	    PRINT_ARRAY("gxy 2:",g_xy2.ptr,g_xy2.len);
		//PRINTF("public ephemeral PQ Key size: %d\n", c_i.g_x.len);
		//PRINTF("secret ephemeral PQ Key size: %d\n", c_i.x.len);
		//PRINT_ARRAY("PK eph:",c_i.g_x.ptr,c_i.g_x.len);
		//PRINT_ARRAY("SK eph:",c_i.x.ptr,c_i.x.len);
	#endif

	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_initiator, rx_initiator, ead_process);
	if (r != ok) {
		goto end;
	}

	PRINT_ARRAY("I_PRK_out", I_PRK_out.ptr, I_PRK_out.len);

	r = prk_out2exporter(SHA_256, &I_PRK_out, &I_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("I_prk_exporter", I_prk_exporter.ptr, I_prk_exporter.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &I_prk_exporter,
			   &I_master_secret);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", I_master_secret.ptr,
		    I_master_secret.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &I_prk_exporter,
			   &I_master_salt);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", I_master_salt.ptr, I_master_salt.len);

#ifdef REPORT_STACK_USAGE
	thread_analyzer_print();
#endif

	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}

/**
 * @brief			A thread in which a Responder instance is executed
 * 
 * @param vec_num 	Test vector number
 * @param dummy2 	unused
 * @param dummy3 	unused
 */
void thread_responder(void *vec_num, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);
    int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("Responder thread started with test vector %d!\n",vec_num_i +1);
	enum err r;
	

	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	c_r.ead_2.len = test_vectors[vec_num_i].ead_2_len;
	c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r.ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r.id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r.cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r.g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r.y.len = test_vectors[vec_num_i].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r.g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r.r.len = test_vectors[vec_num_i].r_raw_len;
	c_r.r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r.sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r.pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;


    struct suite suit_in;
	get_suite((enum suite_label)c_r.suites_r.ptr[c_r.suites_r.len - 1],
				&suit_in);
				  
	PRINTF("Responder SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

    uint8_t PQ_public_random[get_kem_cc_len(suit_in.edhoc_ecdh)];
	c_r.g_y.ptr = PQ_public_random;
	c_r.g_y.len = get_kem_cc_len(suit_in.edhoc_ecdh);

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_responder, rx_responder, ead_process);
	if (r != ok) {
		goto end;
	}

	PRINT_ARRAY("R_PRK_out", R_PRK_out.ptr, R_PRK_out.len);

	r = prk_out2exporter(SHA_256, &R_PRK_out, &R_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("R_prk_exporter", R_prk_exporter.ptr, R_prk_exporter.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &R_prk_exporter,
			   &R_master_secret);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", R_master_secret.ptr,
		    R_master_secret.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &R_prk_exporter,
			   &R_master_salt);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", R_master_salt.ptr, R_master_salt.len);

#ifdef REPORT_STACK_USAGE
	thread_analyzer_print();
#endif

	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}

int test_initiator_responder_interaction(int vec_num)
{
	PRINT_MSG("start initiator_responder_interaction\n");

	/*initiator thread*/
	k_tid_t initiator_tid = k_thread_create(
		&thread_initiator_data, thread_initiator_stack_area,
		K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
		thread_initiator, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);

	/*responder thread*/
	/*k_tid_t responder_tid = k_thread_create(
		&thread_responder_data, thread_responder_stack_area,
		K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
		thread_responder, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);*/

	k_thread_start(&thread_initiator_data);
	//k_thread_start(&thread_responder_data);

	if (0 != k_thread_join(&thread_initiator_data, K_FOREVER)) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(initiator_tid);
	}
	/*if (0 != k_thread_join(&thread_responder_data, K_FOREVER)) {
		PRINT_MSG("responder thread stalled! Aborting.");
		k_thread_abort(responder_tid);
	}*/

	PRINT_MSG("threads completed\n");

	/* check if Initiator and Responder computed the same values */

	zassert_mem_equal__(I_PRK_out.ptr, R_PRK_out.ptr, R_PRK_out.len,
			    "wrong prk_out");

	zassert_mem_equal__(I_prk_exporter.ptr, R_prk_exporter.ptr,
			    R_prk_exporter.len, "wrong prk_exporter");

	zassert_mem_equal__(I_master_secret.ptr, R_master_secret.ptr,
			    R_master_secret.len, "wrong master_secret");

	zassert_mem_equal__(I_master_salt.ptr, R_master_salt.ptr,
			    R_master_salt.len, "wrong master_salt");
	return 0;
}

void t_initiator_responder_interaction1()
{
	MEASURE_LATENCY(test_initiator_responder_interaction(TEST_X5T_NUM));
}

void t_initiator_responder_interaction2()
{
	MEASURE_LATENCY(test_initiator_responder_interaction(TEST_X5CHAIN_NUM));
}