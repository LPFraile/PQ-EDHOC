/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/debug/thread_analyzer.h>
#include <zephyr/sys/time_units.h>
#include <edhoc.h>

#ifdef USE_TEST_EDHOC
#include "edhoc_test_vectors_p256_v16.h"
#endif
#include "latency.h"




/*CPU frecuency*/
#ifdef MEASURE_CLK
#define CPU_CLK 64000000
#define TIME_RATE 1000 /*for ms*/
#endif
/* scheduling priority used by each thread */
#define PRIORITY 7
#ifdef USE_TEST_SIG
#define STACKSIZE_SIG 100000
#endif
#ifdef USE_TEST_KEM
#define STACKSIZE_KEM 120000
#endif
/*Define for testing external trigger*/
#ifdef POWER_MEASUREMENTS
	#include <zephyr/drivers/gpio.h>
	#define LED0_NODE DT_ALIAS(led0)
	#define LED1_NODE DT_ALIAS(led1)
	static const struct gpio_dt_spec led_i = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
	//static const struct gpio_dt_spec led_i = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
	static const struct gpio_dt_spec led_r = GPIO_DT_SPEC_GET(LED1_NODE, gpios);
	
	//#ifndef USE_TEST_EDHOC
	#define LED2_NODE DT_ALIAS(led2)
	static const struct gpio_dt_spec led_e = GPIO_DT_SPEC_GET(LED2_NODE, gpios);
	//#endif
#endif
/*Define interaction number*/
#ifdef USE_INTE_NUM
#define INTERACTION_NUM USE_INTE_NUM
#else
#define INTERACTION_NUM 1
#endif
volatile uint64_t times = INTERACTION_NUM;

//#define MSG_LEN 30
/*KYBER LEVEL 1, FALCON LEVEL 1*/
#ifdef USE_SUIT_7
#define TEST_X5T_NUM 7
#define TEST_X5CHAIN_NUM 8
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 50000
#define STACKSIZE_R 40000
#define MAX_MSG_SIZE 3200
#define USE_SUIT SUITE_7


/*KYBER LEVEL 3, FALCON LEVEL 1*/
#elif USE_SUIT_9
#define TEST_X5T_NUM 9
#define TEST_X5CHAIN_NUM 10
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 50000
#define STACKSIZE_R 40000
#define MAX_MSG_SIZE 3500
#define USE_SUIT SUITE_9

/*HQC LEVEL 1, FALCON LEVEL 1*/
#elif USE_SUIT_10
#define TEST_X5T_NUM 13
#define TEST_X5CHAIN_NUM 13
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 90000
#define STACKSIZE_R 79000
#define MAX_MSG_SIZE 6000
#define USE_SUIT SUITE_10

/*BIKE LEVEL 1, FALCON LEVEL 1*/
#elif USE_SUIT_11
#define TEST_X5T_NUM 14
#define TEST_X5CHAIN_NUM 14
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 120000
#define STACKSIZE_R 50000
#define MAX_MSG_SIZE 2300
#define USE_SUIT SUITE_11

/*KYBER LEVEL 1, DILITHIUM LEVEL 2*/
#elif USE_SUIT_12
#define TEST_X5T_NUM 11
#define TEST_X5CHAIN_NUM 12
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 90000
#define STACKSIZE_R 90000
#define MAX_MSG_SIZE 7104
#define USE_SUIT SUITE_12
/*BIKE LEVEL 1, DILITHIUM LEVEL 2*/
#elif USE_SUIT_13
#define TEST_X5T_NUM 15
#define TEST_X5CHAIN_NUM 15
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 90000
#define STACKSIZE_R 90000
#define MAX_MSG_SIZE 7000
#define USE_SUIT SUITE_13


/*KYBER LEVEL 1, HAWK LEVEL 2*/
#elif USE_SUIT_14
#define TEST_X5T_NUM 16
#define TEST_X5CHAIN_NUM 16
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 50000
#define STACKSIZE_R 30000
#define MAX_MSG_SIZE 7000
#define USE_SUIT SUITE_14

/*KYBER LEVEL 1, HAETAE LEVEL 2*/
#elif USE_SUIT_15
#define TEST_X5T_NUM 17
#define TEST_X5CHAIN_NUM 17
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 80000
#define STACKSIZE_R 85000
#define MAX_MSG_SIZE 7000
#define USE_SUIT SUITE_15

/*KYBER LEVEL 1, OV-IP LEVEL 1*/
#elif USE_SUIT_16
#define TEST_X5T_NUM 18
#define TEST_X5CHAIN_NUM 18 
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 135000
#define STACKSIZE_R 85000
#define MAX_MSG_SIZE 7000
#define USE_SUIT SUITE_16


/*CIPHER SUIT 2 secp256r1 ECDSA* */
#elif USE_SUIT_2
#define TEST_X5T_NUM 2
#define TEST_X5CHAIN_NUM 3 
//#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 50000
#define STACKSIZE_R 40000
#define MAX_MSG_SIZE 800
#define USE_SUIT SUITE_2

#else 
#error "Need to define ciphersuit"

#endif

#ifdef USE_X5CHAIN
#define TEST_NUM TEST_X5CHAIN_NUM
#elif USE_X5T
#define TEST_NUM TEST_X5T_NUM
#else
#error "need to define x5chain or x5t"
#endif


#ifdef USE_TEST_SIG
#include <api.h>
#include <zephyr/random/rand32.h>
#endif



#ifdef MEASURE_CLK
#include <stdio.h>
//#include <zephyr/kernel.h>
#include <zephyr/sys/timeutil.h>
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/clock_control/nrf_clock_control.h>
#include <zephyr/drivers/counter.h>
#include <nrfx_clock.h>
#endif

#ifdef USE_TEST_EDHOC
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
K_SEM_DEFINE(tx_initiator_finished, 0, 1);

/*message exchange buffer*/
uint8_t msg_exchange_buf[MAX_MSG_SIZE];
uint32_t msg_exchange_buf_len = sizeof(msg_exchange_buf);

size_t initiator_tx_size = 0;
size_t responder_tx_size = 0;

int rx_count = 0;
#endif
#ifdef USE_TEST_SIG
K_THREAD_STACK_DEFINE(thread_signature_stack_area, STACKSIZE_SIG);
static struct k_thread thread_signature_data;
#endif
#ifdef USE_TEST_KEM
K_THREAD_STACK_DEFINE(thread_kem_stack_area, STACKSIZE_KEM);
static struct k_thread thread_kem_data;
#endif


#ifdef REPORT_STACK_USAGE
size_t max_size = 0;
size_t max_size_i = 0;
size_t max_size_r = 0;
size_t max_mem_used_i = 0;
size_t max_mem_used_r = 0;
size_t max_mem_used_e = 0;
size_t  keep_max_size(size_t old_val,size_t new_val){
	if(old_val > new_val){
		return old_val;
	}	
	else{
		return new_val;
	}
}
#endif



#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t cycles_i;            
	volatile uint64_t us_i;    

	volatile uint64_t cycles_r;            
	volatile uint64_t us_r;

	volatile uint64_t cycles_e;   
#endif

#ifdef MEASURE_CLK
static const struct device *const clock0 = DEVICE_DT_GET_ONE(nordic_nrf_clock);
static const struct device *const timer0 = DEVICE_DT_GET(DT_NODELABEL(timer0));
uint64_t clk_i;
uint64_t clk_r;
uint64_t clk_e;
uint32_t ctr_start_r;
//uint32_t ctr_end_r;
#endif
#ifdef POWER_MEASUREMENTS   
void configure_triggers(){
	int ret;

	if (!gpio_is_ready_dt(&led_i)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led_i, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}


	if (!gpio_is_ready_dt(&led_r)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led_r, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}
    //#ifndef USE_TEST_EDHOC
	if (!gpio_is_ready_dt(&led_e)) {
		return 0;
	}

	ret = gpio_pin_configure_dt(&led_e, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return 0;
	}
	gpio_pin_set_dt(&led_e, 1);
	//#endif
	gpio_pin_set_dt(&led_i, 1);
	gpio_pin_set_dt(&led_r, 1);
	
}
#endif

#if defined (MEASURE_CLK) || defined(MEASURE_LATENCY_PER_THREAD)
volatile uint64_t  keep_max(volatile uint64_t  old_val,volatile uint64_t  new_val){
	if(old_val > new_val){
		return old_val;
	}	
	else{
		return new_val;
	}
}

volatile uint64_t  keep_min(volatile uint64_t  old_val,volatile uint64_t  new_val){
	if((old_val < new_val) && (old_val!=(uint64_t)0)){
		return old_val;
	}	
	else{

		return new_val;
	}
}
#endif

#ifdef USE_TEST_EDHOC
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
enum err semaphore_take_finished(struct k_sem *sem)
{
	if (k_sem_take(sem, K_FOREVER) != 0) {
		PRINT_MSG("Cannot receive a message!\n");
	} else {
		PRINT_MSG("INITIATOR FINISH\n");
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
volatile uint32_t clock_start_r;
enum err tx_initiator(void *sock, struct byte_array *data)
{
	PRINTF("I: tx_initiator data len: %d\n", data->len);
	initiator_tx_size = initiator_tx_size + data->len;
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	#ifdef POWER_MEASUREMENTS
	PRINTF("Stop Initiator\n");
	gpio_pin_set_dt(&led_i, 1);
	#endif
	#ifdef POWER_MEASUREMENTS  
	PRINTF("Start Responder\n"); 
	gpio_pin_set_dt(&led_r, 0);

	#endif
	semaphore_give(&tx_initiator_completed);
    PRINTF("RX_COUNT %d\n",rx_count);
	
    if(rx_count == 0){
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_start_r = k_cycle_get_32();  
	#endif
	#ifdef MEASURE_CLK
	int rc = counter_get_value(timer0, &ctr_start_r);
	PRINTF("START MEASURE RESPONDER %llu  \n",(uint64_t)ctr_start_r);
	#endif
	}
	rx_count++;


	return ok;
}

enum err tx_responder(void *sock, struct byte_array *data)
{
	
	PRINTF("tx_responder data len: %d\n", data->len);
    responder_tx_size = responder_tx_size + data->len;
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	#ifdef POWER_MEASUREMENTS
	PRINTF("Stop responder\n");
	gpio_pin_set_dt(&led_r, 1);
	#endif
	#ifdef POWER_MEASUREMENTS  
	PRINTF("Start Initiator\n"); 
	gpio_pin_set_dt(&led_i, 0);

	#endif
	//PRINTF("msg_exchange_buf_len: %d\n",msg_exchange_buf_len);
	semaphore_give(&tx_responder_completed);
	
	return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data)
{
	PRINTF("Rx_initiator\n");
	PRINTF("msg_exchange_buf_len: %d\n", msg_exchange_buf_len);
	return semaphore_take(&tx_responder_completed, data->ptr, &data->len);
}
enum err rx_responder(void *sock, struct byte_array *data)
{
	PRINTF("Rx_responder\n");
	PRINTF("msg_exchange_buf_len: %d\n", msg_exchange_buf_len);
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
	struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
			&suit_in);
    #ifndef USE_SUIT_2
	PRINTF("NO use suit 2\n");
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	memcpy(SK,c_i.sk_i.ptr,c_i.sk_i.len);
	memcpy(PK,c_i.pk_i.ptr,c_i.pk_i.len);
	c_i.sk_i.ptr = SK;
	c_i.sk_i.len = get_sk_len(suit_in.edhoc_sign);
	c_i.pk_i.ptr = PK;
	c_i.pk_i.len = get_pk_len(suit_in.edhoc_sign);
    #endif

	//printf("start measure\n");
	#ifdef POWER_MEASUREMENTS
	    PRINTF("Start Initiator\n"); 
		gpio_pin_set_dt(&led_i, 0);

	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
    	volatile uint32_t clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	uint32_t ctr_start;
	uint32_t ctr_end;
	int rc;
	if (!device_is_ready(clock0)) {
		printf("%s: device not ready.\n", clock0->name);
		return;
	}
	if (IS_ENABLED(CONFIG_APP_ENABLE_HFXO)) {
		rc = clock_control_on(clock0, CLOCK_CONTROL_NRF_SUBSYS_HF);
		//printf("Enable HFXO\n");
	}
	else{
		printf("HF is not Enable\n");
	}
		/* Grab the timer. */
	if (!device_is_ready(timer0)) {
		printf("%s: device not ready.\n", timer0->name);
		return;
	}
	rc = counter_start(timer0);
	rc = counter_get_value(timer0, &ctr_start);
	PRINTF("START MEASURE INITIATOR %llu  \n",(uint64_t)ctr_start);
	#endif

    #if defined(GEN_EPH_KEYS) && !defined(USE_SUIT_2)
				  
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
	
	#endif
	#if !defined(GEN_EPH_KEYS) && defined(USE_SUIT_2)

		PRINTF("SUIT 2 with test_vector ephemerals\n")
	#endif
	rx_count = 0;

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
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	clk_i = (uint64_t)ctr_end - (uint64_t)ctr_start;
	PRINTF("STOP MEASURE INITIATOR %llu %llu \n",(uint64_t)ctr_end, clk_i);
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint32_t clock_end = k_cycle_get_32(); 
	cycles_i = (uint64_t)clock_end - (uint64_t)clock_start;            
	us_i = k_cyc_to_us_near64(cycles_i);
	#endif  
	#ifdef POWER_MEASUREMENTS   
	PRINTF("Stop Initiator\n");
	gpio_pin_set_dt(&led_i, 1);
	#endif
	semaphore_give(&tx_initiator_finished);

	

            
	/*printf("Elapsed time initiator:  %d (RTC cycles); %lld (us)\n", cycles_i,    
			us_i); */                                                   
   
#ifdef REPORT_STACK_USAGE
	int err;                                                  
   	size_t unused;
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	max_size_i = keep_max_size(max_size_i, STACKSIZE_I-unused);
	//printf("\rMax used stack on thread_initiator %zu\n",max_size_i);

	if(times == 0)
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
	#ifndef USE_SUIT_2
	PRINTF("NO use suit 2\n");
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	memcpy(SK,c_r.sk_r.ptr,c_r.sk_r.len);
	memcpy(PK,c_r.pk_r.ptr,c_r.pk_r.len);
	c_r.sk_r.ptr = SK;
	c_r.sk_r.len = get_sk_len(suit_in.edhoc_sign);
	c_r.pk_r.ptr = PK;
	c_r.pk_r.len = get_pk_len(suit_in.edhoc_sign);
	#endif			  
	PRINTF("Responder SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

    #ifdef USE_SUIT_2
	PRINTF("USE SUIT 2\n");	
	PRINT_ARRAY("RX public ephemeral DH key", c_r.g_y.ptr, c_r.g_y.len);
	PRINT_ARRAY("RX secret ephemeral DH key", c_r.y.ptr, c_r.y.len);
	#else
	uint8_t PQ_public_random[get_kem_cc_len(suit_in.edhoc_ecdh)];
	c_r.g_y.ptr = PQ_public_random;
	c_r.g_y.len = get_kem_cc_len(suit_in.edhoc_ecdh);
	#endif
	
	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	//rx_count = 0;
    
	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_responder, rx_responder, ead_process);
	if (r != ok) {
		goto end;
	}
    semaphore_take_finished(&tx_initiator_finished);
	#ifdef POWER_MEASUREMENTS  
	PRINTF("Start Responder\n"); 
	gpio_pin_set_dt(&led_r, 0);

	#endif
	PRINT_MSG("Responder derive security context\n");
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
	
	#ifdef MEASURE_CLK
	uint32_t ctr_end_r;
	int rc = counter_get_value(timer0, &ctr_end_r);
	clk_r = (uint64_t)ctr_end_r - (uint64_t)ctr_start_r;
	PRINTF("STOP MEASURE RESPONDER %llu %llu \n",(uint64_t)ctr_end_r, clk_r);
	#endif  
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint32_t clock_end = k_cycle_get_32();   
	cycles_r = (uint64_t)clock_end - (uint64_t)clock_start_r;  
	us_r = k_cyc_to_us_near64(cycles_r);
	#endif 
	#ifdef POWER_MEASUREMENTS   
	PRINTF("Stop responder\n");
	gpio_pin_set_dt(&led_r, 1);
	#endif
    

#ifdef REPORT_STACK_USAGE
	int err;                                                  
   	size_t unused;
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	max_size_r = keep_max_size(max_size_r, STACKSIZE_R-unused);
	//printf("\rMax used stack on thread_respondder %zu\n",max_size_r);
	//printf("\rMax used stack on thread_respondder %zu\n",STACKSIZE_R-unused);

	if(times == 0)
		thread_analyzer_print();
#endif

	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}
#endif

#ifdef USE_TEST_KEM

/**
 * @brief			PQ KEMs thread
 * 
 * @param vec_num 	Test vector number
 */

void thread_kem(void *vec_num){

	int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("test_PQ_KEMs - started with test vector %d!\n",vec_num_i +1);
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


   #ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint32_t clock_start;
	volatile uint32_t clock_end;
	
   #endif
   #ifdef MEASURE_CLK

	uint32_t ctr_start;
	uint32_t ctr_end;
	int rc;
	if (!device_is_ready(clock0)) {
		printf("%s: device not ready.\n", clock0->name);
		return;
	}
	if (IS_ENABLED(CONFIG_APP_ENABLE_HFXO)) {
		rc = clock_control_on(clock0, CLOCK_CONTROL_NRF_SUBSYS_HF);
	}
	else{
		printf("HF is not Enable\n");
	}
		/* Grab the timer. */
	if (!device_is_ready(timer0)) {
		printf("%s: device not ready.\n", timer0->name);
		return;
	}
	
	rc = counter_start(timer0);
	
	#endif
	#ifdef REPORT_STACK_USAGE
		int err;                                                  
		size_t unused;
		size_t usedb;
		size_t usedl;
		size_t initialused;
	#endif
	struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
				&suit_in);
   #ifdef GEN_EPH_KEYS			  
		PRINTF("SUIT kem: %d \n",suit_in.edhoc_ecdh);

		uint8_t PQ_public_random[get_kem_pk_len(suit_in.edhoc_ecdh)];
		uint8_t PQ_secret_random[get_kem_sk_len(suit_in.edhoc_ecdh)];
		c_i.g_x.ptr = PQ_public_random;
		c_i.g_x.len = get_kem_pk_len(suit_in.edhoc_ecdh);
		c_i.x.ptr = PQ_secret_random;
		c_i.x.len = get_kem_sk_len(suit_in.edhoc_ecdh);

		//Measure the KEM key  generation
	
		#ifdef POWER_MEASUREMENTS
		gpio_pin_set_dt(&led_i, 0);
		#endif
		#ifdef REPORT_STACK_USAGE
		err = k_thread_stack_space_get(k_current_get(), &unused);
		if (err) {
			printf("ERROR in read thread memory\n");	
			unused = 0;
		}
		usedb = STACKSIZE_KEM-unused;
		initialused =usedb;
		#endif
		
		#ifdef MEASURE_LATENCY_PER_THREAD
    	clock_start = k_cycle_get_32();
		#endif
		#ifdef MEASURE_CLK
		rc = counter_get_value(timer0, &ctr_start);
		#endif
		r = ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &c_i.x,&c_i.g_x);
		if (r != ok) {
			PRINTF("An error has occurred. Error code: %d\n", r);
			return;
		}
		#ifdef MEASURE_CLK
		rc = counter_get_value(timer0, &ctr_end);
		clk_i = (uint64_t)ctr_end - (uint64_t)ctr_start;
		#endif
		#ifdef MEASURE_LATENCY_PER_THREAD
		clock_end = k_cycle_get_32();   
		cycles_i = (uint64_t)clock_end - (uint64_t)clock_start;  
		#endif  

		#ifdef REPORT_STACK_USAGE
		err = k_thread_stack_space_get(k_current_get(), &unused);
		if (err) {
			printf("ERROR in read thread memory\n");	
			unused = 0;
		}
		usedl = STACKSIZE_KEM-unused;
		max_mem_used_i = keep_max_size(max_mem_used_i,usedl - usedb);
		#endif
		#ifdef POWER_MEASUREMENTS
		gpio_pin_set_dt(&led_i, 1);
		#endif
	


	#endif

	PRINTF("CC len:%d",get_kem_cc_len(suit_in.edhoc_ecdh));
	uint8_t CIPHE[get_kem_cc_len(suit_in.edhoc_ecdh)];
	uint8_t SS[get_kem_ss_len(suit_in.edhoc_ecdh)];
	uint8_t SS2[get_kem_ss_len(suit_in.edhoc_ecdh)];
	struct byte_array cc;
	cc.ptr = CIPHE;
	cc.len = get_kem_cc_len(suit_in.edhoc_ecdh);
	struct byte_array g_xy;
	g_xy.ptr = SS;
	g_xy.len = get_kem_ss_len(suit_in.edhoc_ecdh);
	struct byte_array g_xy2;
	g_xy2.ptr = SS2;
	g_xy2.len = get_kem_ss_len(suit_in.edhoc_ecdh);
	PRINT_MSG("Before encapsulate\n");

	//Measure the KEM encapsulation funtion

	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_r, 0);
	#endif
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedb = STACKSIZE_KEM-unused;
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_start);
	#endif
	
	r = kem_encapsulate(suit_in.edhoc_ecdh,&c_i.g_x,&cc,&g_xy);
		if (r != ok) {
		PRINTF("An error has occurred. Error code: %d\n", r);
		return;
	}
	
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	clk_r = (uint64_t)ctr_end - (uint64_t)ctr_start;
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_end = k_cycle_get_32();   
	cycles_r = (uint64_t)clock_end - (uint64_t)clock_start;  
	#endif   
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedl = STACKSIZE_KEM-unused;
	max_mem_used_r = keep_max_size(max_mem_used_r,usedl - usedb);
	#endif
	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_r, 1);
	#endif		    
 
	


	PRINT_MSG("encapsulate correct\n");
	PRINT_ARRAY("gxy:",g_xy.ptr,g_xy.len);
	PRINT_ARRAY("cc",cc.ptr,cc.len);

	///Measure the KEM decapsulation funtion

	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_e, 0);
	#endif
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedb = STACKSIZE_KEM-unused;
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_start);
	#endif

	r = kem_decapsulate(suit_in.edhoc_ecdh, &cc, &c_i.x, &g_xy2);
	if (r != ok) {
		PRINTF("An error has occurred. Error code: %d\n", r);
		return;
	}
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	clk_e = (uint64_t)ctr_end - (uint64_t)ctr_start;
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_end = k_cycle_get_32();   
	cycles_e = (uint64_t)clock_end - (uint64_t)clock_start;  
	#endif  
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedl = STACKSIZE_KEM-unused;
	max_mem_used_e = keep_max_size(max_mem_used_e,usedl - usedb);
	#endif
	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_e, 1);
	#endif		    



	PRINT_ARRAY("gxy 1:",g_xy2.ptr,g_xy2.len);
	PRINT_ARRAY("gxy 2:",g_xy.ptr,g_xy.len);

            
	zassert_mem_equal__(g_xy.ptr, g_xy2.ptr, g_xy.len,
			    "wrong ss on KEM");
	
#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	max_size = keep_max_size(max_size, STACKSIZE_KEM-unused-initialused);
	//printf("\rMax used stack on thread_signature %zu\n",max_size);

	if(times == 0)
		thread_analyzer_print();

#endif
	return;
	

}

#endif

#ifdef USE_TEST_SIG
/**
 * @brief			PQ siggnature test thread
 * 
 * @param vec_num 	Test vector number
 */

void thread_signature(void *vec_num){

	PRINT_MSG("Signature thread started!\n");
	enum err r;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;
	struct suite suit_in;
    volatile uint32_t clock_start;
	volatile uint32_t clock_end;
	
	#ifdef MEASURE_CLK
	uint32_t ctr_start;
	uint32_t ctr_end;
	int rc;
	if (!device_is_ready(clock0)) {
		printf("%s: device not ready.\n", clock0->name);
		return;
	}
	if (IS_ENABLED(CONFIG_APP_ENABLE_HFXO)) {
		rc = clock_control_on(clock0, CLOCK_CONTROL_NRF_SUBSYS_HF);
		//printf("Enable HFXO\n");
	}
	else{
		printf("HF is not Enable\n");
	}
		/* Grab the timer. */
	if (!device_is_ready(timer0)) {
		printf("%s: device not ready.\n", timer0->name);
		return;
	}
	rc = counter_start(timer0);
	#endif
	
	#ifdef REPORT_STACK_USAGE
	int err;                                                  
   	size_t unused;
	size_t usedb;
	size_t usedl;
	size_t initialused;
	#endif

	#ifdef AUTH_KEY_GEN
	int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("test_PQ_signatures - stimate size with test vector %d!\n",vec_num_i +1);

	get_suite(USE_SUIT,&suit_in);
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	c_i.sk_i.ptr = SK;
	c_i.sk_i.len = get_sk_len(suit_in.edhoc_sign);
	c_i.pk_i.ptr = PK;
	c_i.pk_i.len = get_pk_len(suit_in.edhoc_sign);

    #ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedb = STACKSIZE_SIG-unused;
	initialused =usedb;
	//printf("used before key gen %zu\n",usedb);
	#endif
	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_e, 0);
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_start);
	//printf("Start %d\n",ctr_start);
	#endif

	r = static_signature_key_gen(suit_in.edhoc_sign,&c_i.sk_i,&c_i.pk_i);
	if (r != ok) {
	printf("An error has occurred. Error code: %d\n", r);
	return;
	}	
	
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	//printf("End %d\n",ctr_end);
	clk_e = (uint64_t)ctr_end - (uint64_t)ctr_start;
	//printf("CLK %d\n",clk_i);
	#endif 
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_end = k_cycle_get_32();   
	cycles_e = (uint64_t)clock_end - (uint64_t)clock_start;  
	#endif   
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedl = STACKSIZE_SIG-unused;
	/*printf("used later key gen %zu\n",usedl);
	printf("used on key gen %zu\n",usedl - usedb);*/
	max_mem_used_i = keep_max_size(max_mem_used_i,usedl - usedb);
	#endif
	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_e, 1);
	#endif		    
	#else
	int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("test_PQ_KEMs - started with test vector %d!\n",vec_num_i +1);
	//enum err r;

	//struct other_party_cred cred_r;
	//struct edhoc_initiator_context c_i;

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
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
				&suit_in);

	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	memcpy(SK,c_i.sk_i.ptr,c_i.sk_i.len);
	memcpy(PK,c_i.pk_i.ptr,c_i.pk_i.len);
	c_i.sk_i.ptr = SK;
	c_i.sk_i.len = get_sk_len(suit_in.edhoc_sign);
	c_i.pk_i.ptr = PK;
	c_i.pk_i.len = get_pk_len(suit_in.edhoc_sign);
	
	#endif

	/*printf("Sk size:%d\n",get_sk_len(suit_in.edhoc_sign));
	printf("Pk size:%d\n", get_pk_len(suit_in.edhoc_sign));
	printf("Sig size:%d\n",get_signature_len(suit_in.edhoc_sign));	
    */
	
	PRINT_ARRAY("pk",c_i.pk_i.ptr,c_i.pk_i.len);
	PRINT_ARRAY("sk",c_i.sk_i.ptr,c_i.sk_i.len);
				  
	PRINTF("SUIT Signature: %d \n",suit_in.edhoc_sign);
 

	uint8_t SIGN1[get_signature_len(suit_in.edhoc_sign)];
	struct byte_array sig1;
	sig1.ptr = SIGN1;
	sig1.len = get_signature_len(suit_in.edhoc_sign);

    PRINTF("Signature len: %d\n",sig1.len);
	PRINT_ARRAY("sig in",sig1.ptr,sig1.len);
	uint8_t message[SIG_STRUCT_SIZE];

	sys_rand_get(message, sizeof(message));


	struct byte_array msg;
	msg.ptr = message;
	msg.len = SIG_STRUCT_SIZE;

	
	PRINT_MSG("Before signature\n");

	//Measure the signature funtion

	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_i, 0);
	#endif
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedb = STACKSIZE_SIG-unused;
	//printf("used before sign %zu\n",usedb);
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_start);
	//printf("Start %d\n",ctr_start);
	#endif
    
	r = sign_signature(suit_in.edhoc_sign,&c_i.sk_i, &msg, sig1.ptr, &sig1.len);
	
	if (r != ok) {
		printf("An error has occurred. Error code: %d\n", r);
		return;
	}
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	//printf("End %d\n",ctr_end);
	clk_i = (uint64_t)ctr_end - (uint64_t)ctr_start;
	//printf("CLK %d\n",clk_i);
	#endif 
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_end = k_cycle_get_32();   
	cycles_i = (uint64_t)clock_end - (uint64_t)clock_start;  
	//printf("CICLES TO SIGN: %d\n",cycles_i);
	#endif  
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedl = STACKSIZE_SIG-unused;
	/*printf("used later sign %zu\n",usedl);
	printf("used on sign %zu\n",usedl - usedb);*/
	max_mem_used_r = keep_max_size(max_mem_used_r,usedl - usedb);
	#endif
	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_i, 1);
	#endif		    
 

	
	///Measure the signature verify function

	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_r, 0);
	#endif
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedb = STACKSIZE_SIG-unused;
	//printf("used before sign %zu\n",usedb);
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_start);
	#endif

	r = sign_verify(suit_in.edhoc_sign, &c_i.pk_i, &msg, &sig1);
	if (r != ok) {
		printf("An error has occurred in sign verify. Error code: %d\n", r);
		//return r;
	}
	
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	clk_r = (uint64_t)ctr_end - (uint64_t)ctr_start;
	#endif 
	#ifdef MEASURE_LATENCY_PER_THREAD
	clock_end = k_cycle_get_32();   
	cycles_r = (uint64_t)clock_end - (uint64_t)clock_start;  
	//printf("CICLES TO VERIFY: %d\n",cycles_r);
	#endif  
	#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	usedl = STACKSIZE_SIG-unused;
	/*printf("used later verify %zu\n",usedl);
	printf("used on verify %zu\n",usedl - usedb);*/
	max_mem_used_e = keep_max_size(max_mem_used_e,usedl - usedb);
	#endif
	#ifdef POWER_MEASUREMENTS
	gpio_pin_set_dt(&led_r, 1);
	#endif		    



	zassert_ok(r,"error at signature verify",r);
	PRINTF("signature corrrect\n");	                                                  
   

#ifdef REPORT_STACK_USAGE
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	max_size = keep_max_size(max_size, STACKSIZE_SIG-unused - initialused);
	//printf("\rMax used stack on thread_signature %zu\n",max_size);

	if(times == 0)
		thread_analyzer_print();

#endif
	return;

}

int test_PQ_signature(int vec_num){
	/*signature thread*/
	k_tid_t sig_tid = k_thread_create(
		&thread_signature_data, thread_signature_stack_area,
		K_THREAD_STACK_SIZEOF(thread_signature_stack_area),
		thread_signature, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);
	k_thread_start(&thread_signature_data);	
	if (0 != k_thread_join(&thread_signature_data, K_FOREVER)) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(sig_tid);
	}
	PRINT_MSG("signature thread completed\n");
	return 0;
}

#endif

#ifdef USE_TEST_KEM
int test_PQ_KEMs(int vec_num){
	/*signature thread*/
	k_tid_t kem_tid = k_thread_create(
		&thread_kem_data, thread_kem_stack_area,
		K_THREAD_STACK_SIZEOF(thread_kem_stack_area),
		thread_kem, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);
	k_thread_start(&thread_kem_data);	
	if (0 != k_thread_join(&thread_kem_data, K_FOREVER)) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(kem_tid);
	}
	PRINT_MSG("signature thread completed\n");
	return 0;
}
#endif

#ifdef USE_TEST_EDHOC
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
	k_tid_t responder_tid = k_thread_create(
		&thread_responder_data, thread_responder_stack_area,
		K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
		thread_responder, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);

	k_thread_start(&thread_initiator_data);
	k_thread_start(&thread_responder_data);

	if (0 != k_thread_join(&thread_initiator_data, K_FOREVER)) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(initiator_tid);
	}
	if (0 != k_thread_join(&thread_responder_data, K_FOREVER)) {
		PRINT_MSG("responder thread stalled! Aborting.");
		k_thread_abort(responder_tid);
	}

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
#endif
/*void t_initiator_responder_interaction1()
{
	initiator_tx_size = 0;
	responder_tx_size = 0;
	MEASURE_LATENCY(test_initiator_responder_interaction(TEST_X5T_NUM));
	printf("INITATOR TX APLICATION MESSAGE SEND: %d\n",initiator_tx_size);
	printf("RESPONDER TX APLICATION MESSAGE SEND: %d\n",responder_tx_size);
	printf("TOTAL APLICATION MESSAGE SIZE: %d\n",responder_tx_size+initiator_tx_size);
}

void t_initiator_responder_interaction2()
{
	initiator_tx_size = 0;
	responder_tx_size = 0;
	MEASURE_LATENCY(test_initiator_responder_interaction(TEST_X5CHAIN_NUM));
	printf("INITATOR TX APLICATION MESSAGE SEND: %d\n",initiator_tx_size);
	printf("RESPONDER TX APLICATION MESSAGE SEND: %d\n",responder_tx_size);
	printf("TOTAL APLICATION MESSAGE SIZE: %d\n",responder_tx_size+initiator_tx_size);
}*/

#ifdef USE_TEST_KEM

void t_pq_kems(){
	 
	struct suite suit_in;
	get_suite(USE_SUIT,&suit_in);
	//printf(" suit signature %d\n",suit_in.edhoc_ecdh);
	#ifdef POWER_MEASUREMENTS
		configure_triggers();    
	#endif
    
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t cycles_total_i = 0;            
	volatile uint64_t cycles_total_r = 0;  
	volatile uint64_t cycles_total_e = 0;  
	volatile uint64_t cycles_max_i = 0;
	volatile uint64_t cycles_min_i = 0;
	volatile uint64_t cycles_max_r = 0;
	volatile uint64_t cycles_min_r = 0;
	volatile uint64_t cycles_max_e = 0;
	volatile uint64_t cycles_min_e = 0;
	
	#endif
	#ifdef MEASURE_CLK
	volatile uint64_t clk_total_i = 0;            
	volatile uint64_t clk_total_r = 0;  
	volatile uint64_t clk_total_e = 0;  
	volatile uint64_t clk_max_i = 0;
	volatile uint64_t clk_min_i = 0;
	volatile uint64_t clk_max_r = 0;
	volatile uint64_t clk_min_r = 0;
	volatile uint64_t clk_max_e = 0;
	volatile uint64_t clk_min_e = 0;
	
	#endif
    int value = 0;
	while(times>0){
		printk("\rInteractions: %d", value);
		value++;
		times--;
		MEASURE_LATENCY(test_PQ_KEMs(TEST_X5T_NUM));
		#ifdef MEASURE_LATENCY_PER_THREAD
		cycles_total_i = cycles_total_i + cycles_i;
		cycles_total_r = cycles_total_r + cycles_r;
		cycles_total_e = cycles_total_e + cycles_e;
		cycles_max_i = keep_max(cycles_max_i,cycles_i);
		cycles_max_r = keep_max(cycles_max_r,cycles_r);
		cycles_min_i = keep_min(cycles_min_i,cycles_i);
		cycles_min_r = keep_min(cycles_min_r,cycles_r);
		cycles_max_e = keep_max(cycles_max_e,cycles_e);
		cycles_min_e = keep_min(cycles_min_e,cycles_e);

		#endif 
		#ifdef MEASURE_CLK
		uint64_t rate = CPU_CLK / (uint64_t)counter_get_frequency(timer0);
		clk_total_i = clk_total_i + clk_i*rate;
		clk_total_r = clk_total_r + clk_r*rate;
		clk_total_e = clk_total_e + clk_e*rate;
		clk_max_i = keep_max(clk_max_i,clk_i*rate);
		clk_max_r = keep_max(clk_max_r,clk_r*rate);
		clk_min_i = keep_min(clk_min_i,clk_i*rate);
		clk_min_r = keep_min(clk_min_r,clk_r*rate);
		clk_max_e = keep_max(clk_max_e,clk_e*rate);
		clk_min_e = keep_min(clk_min_e,clk_e*rate);
		/*printf("cycles i %llu\n",clk_i);
		printf("cycles r %llu\n",clk_r);
		printf("cycles e %llu\n",clk_e);
		printf("cycles total i %llu\n",clk_total_i);
		printf("cycles total r %llu\n",clk_total_r);
		printf("cycles total e %llu\n",clk_total_e);
		printf("cycles min i %llu\n",clk_min_i);
		printf("cycles min r %llu\n",clk_min_r);
		printf("cycles min e %llu\n",clk_min_e);*/
		#endif                                                   
	}
	printf("---------------------------------------------------------------------\n");
	printf("Interaction number: %d\n",INTERACTION_NUM);
	printf("KEM suit: %d\n",suit_in.edhoc_ecdh);
	printf("KEM pk: %d\n",get_kem_pk_len(suit_in.edhoc_ecdh));
	printf("KEM cc: %d\n",get_kem_cc_len(suit_in.edhoc_ecdh));
	#ifdef REPORT_STACK_USAGE
	printf("---------------------------------------------------------------------\n");
	printf("Stack usage\n");
	printf("%-25s %-15s %-15s %-15s\n", "Total kem thread", "Key-gen", "Enc.", "Dec.");
	printf("%-25zu %-15zu  %-15zu  %-15zu \n",max_size,max_mem_used_i,max_mem_used_r,max_mem_used_e);
	printf("---------------------------------------------------------------------\n");
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t us_total_i = k_cyc_to_us_near64(cycles_total_i/INTERACTION_NUM );  
	volatile uint64_t us_total_r = k_cyc_to_us_near64(cycles_total_r/INTERACTION_NUM);
	volatile uint64_t us_total_e = k_cyc_to_us_near64(cycles_total_e/INTERACTION_NUM);

	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (RTC cycles)", "AVG", "Min", "Max");	
	printf("%-25s %-15llu %-15llu %-15llu\n", "KEM key gen", cycles_total_i/INTERACTION_NUM, cycles_min_i, cycles_max_i);
	printf("%-25s %-15llu %-15llu %-15llu\n", "KEM key enc", cycles_total_r/INTERACTION_NUM, cycles_min_r, cycles_max_r);
	printf("%-25s %-15llu %-15llu %-15llu\n", "KEM key dec", cycles_total_e/INTERACTION_NUM, cycles_min_e, cycles_max_e);
    printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (us)", "AVG", "Min", "Max");
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "KEM key gen", us_total_i, k_cyc_to_us_near64(cycles_min_i), k_cyc_to_us_near64(cycles_max_i));
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "KEM key enc", us_total_r, k_cyc_to_us_near64(cycles_min_r), k_cyc_to_us_near64(cycles_max_r));
    printf("%-25s %-15lld  %-15lld  %-15lld \n", "KEM key dec", us_total_e, k_cyc_to_us_near64(cycles_min_e), k_cyc_to_us_near64(cycles_max_e));
	#endif

	#ifdef MEASURE_CLK
	printf("----------------------------------------------------------------------\n");
	printf("%-15s %-15s %-15s %-15s\n", "time (CLK)", "KEM key gen", "KEM key enc", "KEM key dec");
	printf("%-15s AVG:%-15llu & AVG: %-15llu & AVG:%-15llu\n", "", clk_total_i/INTERACTION_NUM, clk_total_r/INTERACTION_NUM,clk_total_e/INTERACTION_NUM );
	printf("%-15s MIN:%-15llu & MIN: %-15llu & MIN:%-15llu\n", "", clk_min_i, clk_min_r, clk_min_e);
	printf("%-15s MAX:%-15llu & MAX: %-15llu & MAX:%-15llu\n", "", clk_max_i, clk_max_r, clk_max_e);
    printf("----------------------------------------------------------------------\n");
	printf("%-15s %-15s %-15s %-15s\n", "time (us)", "KEM key gen", "KEM key enc", "KEM key dec");
	printf("%-15s %-15.3f & %-15.4f & %-15.4f \n","", ((float)clk_total_i*TIME_RATE/CPU_CLK)/INTERACTION_NUM, ((float)clk_total_r*TIME_RATE/CPU_CLK)/INTERACTION_NUM,((float)clk_total_e*TIME_RATE/CPU_CLK)/INTERACTION_NUM);
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (CLKs)", "AVG", "Min", "Max");
	printf("%-25s %-15llu %-15llu %-15llu\n", "KEM key gen", clk_total_i/INTERACTION_NUM, clk_min_i, clk_max_i);
	printf("%-25s %-15llu %-15llu %-15llu\n", "KEM key enc", clk_total_r/INTERACTION_NUM, clk_min_r, clk_max_r);
	printf("%-25s %-15llu %-15llu %-15llu\n", "KEM key dec", clk_total_e/INTERACTION_NUM, clk_min_e, clk_max_e);
    printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (ms)", "AVG", "Min", "Max");
	printf("%-25s %-15.3f  %-15.4f  %-15.4f \n", "KEM key gen", ((float)clk_total_i*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_i*TIME_RATE/CPU_CLK, (float)clk_max_i*TIME_RATE/CPU_CLK);
	printf("%-25s %-15.4f  %-15.4f  %-15.4f \n", "KEM key enc", ((float)clk_total_r*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_r*TIME_RATE/CPU_CLK, (float)clk_max_r*TIME_RATE/CPU_CLK);
    printf("%-25s %-15.4f  %-15.4f  %-15.4f \n", "KEM key dec", ((float)clk_total_e*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_e*TIME_RATE/CPU_CLK, (float)clk_max_e*TIME_RATE/CPU_CLK);
	
	#endif
}
#endif

#ifdef USE_TEST_SIG
void t_pq_signatures(){
	//printf(" start\n");
	struct byte_array suite; 
	struct suite suit_in;
	//suite.len = test_vectors[TEST_X5T_NUM].SUITES_I_len;
	//suite.ptr = (uint8_t *)test_vectors[TEST_X5T_NUM].SUITES_I;
	//get_suite((enum suite_label)suite.ptr[suite.len - 1], &suit_in);
	get_suite(USE_SUIT,&suit_in);
	//printf(" suit signature %d\n",suit_in.edhoc_sign);
	#ifdef POWER_MEASUREMENTS
		configure_triggers();    
	#endif
    
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t cycles_total_i = 0;            
	volatile uint64_t cycles_total_r = 0;  
	volatile uint64_t cycles_total_e = 0;  
	volatile uint64_t cycles_max_i = 0;
	volatile uint64_t cycles_min_i = 0;
	volatile uint64_t cycles_max_r = 0;
	volatile uint64_t cycles_min_r = 0;
	volatile uint64_t cycles_max_e = 0;
	volatile uint64_t cycles_min_e = 0;
	#endif

	#ifdef MEASURE_CLK
	volatile uint64_t clk_total_i = 0;            
	volatile uint64_t clk_total_r = 0;  
	volatile uint64_t clk_total_e = 0;  
	volatile uint64_t clk_max_i = 0;
	volatile uint64_t clk_min_i = 0;
	volatile uint64_t clk_max_r = 0;
	volatile uint64_t clk_min_r = 0;
	volatile uint64_t clk_max_e = 0;
	volatile uint64_t clk_min_e = 0;
	#endif
    int value=0;
	while(times>0){
		printk("\rInteractions: %d", value);
		value++;
		times--;
		MEASURE_LATENCY(test_PQ_signature(TEST_X5T_NUM));
		#ifdef MEASURE_LATENCY_PER_THREAD
		cycles_total_i = cycles_total_i + cycles_i;
		cycles_total_r = cycles_total_r + cycles_r;
		cycles_total_e = cycles_total_e + cycles_e;
		cycles_max_i = keep_max(cycles_max_i,cycles_i);
		cycles_max_r = keep_max(cycles_max_r,cycles_r);
		cycles_max_e = keep_max(cycles_max_e,cycles_e);
		cycles_min_i = keep_min(cycles_min_i,cycles_i);
		cycles_min_r = keep_min(cycles_min_r,cycles_r);
		cycles_min_e = keep_min(cycles_min_e,cycles_e);
		#endif
		#ifdef MEASURE_CLK
		uint64_t rate = CPU_CLK / (uint64_t)counter_get_frequency(timer0);
		clk_total_i = clk_total_i + clk_i*rate;
		clk_total_r = clk_total_r + clk_r*rate;
		clk_total_e = clk_total_e + clk_e*rate;
		clk_max_i = keep_max(clk_max_i,clk_i*rate);
		clk_max_r = keep_max(clk_max_r,clk_r*rate);
		clk_max_e = keep_max(clk_max_e,clk_e*rate);
		clk_min_i = keep_min(clk_min_i,clk_i*rate);
		clk_min_r = keep_min(clk_min_r,clk_r*rate);
		clk_min_e = keep_min(clk_min_e,clk_e*rate);
		#endif                                                      
	}
	printf("---------------------------------------------------------------------\n");
    printf("Interaction number: %d\n",INTERACTION_NUM);
	printf("Signature suit: %d\n",suit_in.edhoc_sign);
	printf("SIG pk: %d\n",get_pk_len(suit_in.edhoc_sign));
	printf("SIG sig: %d\n", get_signature_len(suit_in.edhoc_sign));
	#ifdef REPORT_STACK_USAGE
	printf("---------------------------------------------------------------------\n");
	printf("Stack usage\n");
	printf("%-25s %-15s %-15s %-15s\n", "Total signature thread", "Key-gen", "Sign", "Verify");
	printf("%-25zu %-15zu  %-15zu  %-15zu \n",max_size,max_mem_used_i,max_mem_used_r,max_mem_used_e);
	printf("---------------------------------------------------------------------\n");
	#endif
	printf("MESSAGE Signature Size: %d (aproached with KEM %d)\n",SIG_STRUCT_SIZE,suit_in.edhoc_ecdh);
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t us_total_i = k_cyc_to_us_near64(cycles_total_i/INTERACTION_NUM );  
	volatile uint64_t us_total_r = k_cyc_to_us_near64(cycles_total_r/INTERACTION_NUM);
	volatile uint64_t us_total_e = k_cyc_to_us_near64(cycles_total_e/INTERACTION_NUM);
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (RTC cycles)", "AVG", "Min", "Max");
	#ifdef AUTH_KEY_GEN
	printf("%-25s %-15llu %-15llu %-15llu\n", "PQ Key gen.", cycles_total_e/INTERACTION_NUM, cycles_min_e, cycles_max_e);
	#endif
	printf("%-25s %-15llu %-15llu %-15llu\n", "PQ signature", cycles_total_i/INTERACTION_NUM, cycles_min_i, cycles_max_i);
	printf("%-25s %-15llu %-15llu %-15llu\n", "PQ verify", cycles_total_r/INTERACTION_NUM, cycles_min_r, cycles_max_r);
    printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (us)", "AVG", "Min", "Max");
	#ifdef AUTH_KEY_GEN
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "PQ signature", us_POWER_MEASUREMENTS=otal_e, k_cyc_to_us_near64(cycles_min_e), k_cyc_to_us_near64(cycles_max_e));
	#endif
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "PQ signature", us_total_i, k_cyc_to_us_near64(cycles_min_i), k_cyc_to_us_near64(cycles_max_i));
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "PQ verify", us_total_r, k_cyc_to_us_near64(cycles_min_r), k_cyc_to_us_near64(cycles_max_r));
	#endif

	#ifdef MEASURE_CLK

	printf("----------------------------------------------------------------------\n");
	printf("%-15s %-15s %-15s %-15s\n", "time (CLK)", "KEM key gen", "Sig.", "Verify");
	printf("%-15s AVG:%-15llu & AVG: %-15llu & AVG:%-15llu\n", "", clk_total_e/INTERACTION_NUM, clk_total_i/INTERACTION_NUM,clk_total_r/INTERACTION_NUM );
	printf("%-15s MIN:%-15llu & MIN: %-15llu & MIN:%-15llu\n", "", clk_min_e, clk_min_i, clk_min_r);
	printf("%-15s MAX:%-15llu & MAX: %-15llu & MAX:%-15llu\n", "", clk_max_e, clk_max_i, clk_max_r);
    printf("----------------------------------------------------------------------\n");
	printf("%-15s %-15s %-15s %-15s\n", "time (us)", "KEM key gen", "Sig.", "Verify");
	printf("%-15s %-15.3f & %-15.4f & %-15.4f \n","", ((float)clk_total_e*TIME_RATE/CPU_CLK)/INTERACTION_NUM, ((float)clk_total_i*TIME_RATE/CPU_CLK)/INTERACTION_NUM,((float)clk_total_r*TIME_RATE/CPU_CLK)/INTERACTION_NUM);
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (CLK)", "AVG", "Min", "Max");
	#ifdef AUTH_KEY_GEN
	printf("%-25s %-15llu %-15llu %-15llu\n", "PQ key gen.", clk_total_e/INTERACTION_NUM, clk_min_e, clk_max_e);
	#endif
	printf("%-25s %-15llu %-15llu %-15llu\n", "PQ signature", clk_total_i/INTERACTION_NUM, clk_min_i, clk_max_i);
	printf("%-25s %-15llu %-15llu %-15llu\n", "PQ verify", clk_total_r/INTERACTION_NUM, clk_min_r, clk_max_r);
    printf("----------------------------------------------------------------------\n");
	printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (ms)", "AVG", "Min", "Max");
	#ifdef AUTH_KEY_GEN
	printf("%-25s %-15.4f  %-15.4f  %-15.4f \n", "PQ key gen.", ((float)clk_total_e*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_e*TIME_RATE/CPU_CLK, (float)clk_max_e*TIME_RATE/CPU_CLK);
	#endif
	printf("%-25s %-15.3f  %-15.4f  %-15.4f \n", "PQ signature", ((float)clk_total_i*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_i*TIME_RATE/CPU_CLK, (float)clk_max_i*TIME_RATE/CPU_CLK);
	printf("%-25s %-15.4f  %-15.4f  %-15.4f \n", "PQ verify", ((float)clk_total_r*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_r*TIME_RATE/CPU_CLK, (float)clk_max_r*TIME_RATE/CPU_CLK);
   
	#endif
}
#endif

#ifdef USE_TEST_EDHOC
void t_initiator_responder_100_interaction()
{
	//printf(" start\n");

	struct byte_array suite; 
	struct suite suit_in;
	//suite.len = test_vectors[TEST_X5T_NUM].SUITES_I_len;
	//suite.ptr = (uint8_t *)test_vectors[TEST_X5T_NUM].SUITES_I;
	//get_suite((enum suite_label)suite.ptr[suite.len - 1], &suit_in);
	get_suite(USE_SUIT,&suit_in);
	//printf(" suit signature %d\n",suit_in.edhoc_sign);
	#ifdef POWER_MEASUREMENTS
		configure_triggers();    
	#endif
	k_sleep(K_SECONDS(3));
    
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t cycles_total_i = 0;            
	volatile uint64_t cycles_total_r = 0;  
	volatile uint64_t cycles_max_i = 0;
	volatile uint64_t cycles_min_i = 0;
	volatile uint64_t cycles_max_r = 0;
	volatile uint64_t cycles_min_r = 0;
	#endif

	#ifdef MEASURE_CLK
	volatile uint64_t clk_total_i = 0;            
	volatile uint64_t clk_total_r = 0;  
	volatile uint64_t clk_max_i = 0;
	volatile uint64_t clk_min_i = 0;
	volatile uint64_t clk_max_r = 0;
	volatile uint64_t clk_min_r = 0;
	#endif
    int value  = 0;
	while(times>0){
		printk("\rInteractions: %d", value);
		#ifdef POWER_MEASUREMENTS
		gpio_pin_set_dt(&led_e, 0);
		k_sleep(K_MSEC(20));
		#endif
		value++;
		times--;
		initiator_tx_size = 0;
		responder_tx_size = 0; 
		MEASURE_LATENCY(test_initiator_responder_interaction(TEST_NUM));
		
		#ifdef POWER_MEASUREMENTS
		gpio_pin_set_dt(&led_e, 1);
		k_sleep(K_MSEC(2000));
		#endif
		#ifdef MEASURE_LATENCY_PER_THREAD
		cycles_total_i = cycles_total_i + cycles_i;
		cycles_total_r = cycles_total_r + cycles_r;
		cycles_max_i = keep_max(cycles_max_i,cycles_i);
		cycles_max_r = keep_max(cycles_max_r,cycles_r);
		cycles_min_i = keep_min(cycles_min_i,cycles_i);
		cycles_min_r = keep_min(cycles_min_r,cycles_r);
		#endif      
		#ifdef MEASURE_CLK
		uint64_t rate = CPU_CLK / (uint64_t)counter_get_frequency(timer0);
		clk_total_i = clk_total_i + clk_i*rate;
		clk_total_r = clk_total_r + clk_r*rate;
		clk_max_i = keep_max(clk_max_i,clk_i*rate);
		clk_max_r = keep_max(clk_max_r,clk_r*rate);
		clk_min_i = keep_min(clk_min_i,clk_i*rate);
		clk_min_r = keep_min(clk_min_r,clk_r*rate);
		#endif                                                      
	}
	printf("---------------------------------------------------------------------\n");
    printf("Interaction number: %d\n",INTERACTION_NUM);
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "", "Test-vector", "KEM", "Signature");
	printf("%-25s %-15d %-15d %-15d\n", "CIPHER SUIT", TEST_NUM,suit_in.edhoc_ecdh,suit_in.edhoc_sign);
	#ifdef REPORT_STACK_USAGE
	printf("---------------------------------------------------------------------\n");
	printf("Max usage stack initiator thread: %zu\n",max_size_i);
	printf("Max usage stack responder thread : %zu\n",max_size_r);
	printf("---------------------------------------------------------------------\n");
	#endif
	printf("%-25s %-15s %-15s %-15s\n", "", "Initiator", "Responder", "Total");
	printf("%-25s %-15d %-15d %-15d\n", "TX APP MSG", initiator_tx_size,responder_tx_size, responder_tx_size+initiator_tx_size);
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint64_t us_total_i = k_cyc_to_us_near64(cycles_total_i/INTERACTION_NUM );  
	volatile uint64_t us_total_r = k_cyc_to_us_near64(cycles_total_r/INTERACTION_NUM);
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (RTC cycles)", "AVG", "Min", "Max");
	printf("%-25s %-15llu %-15llu %-15llu\n", "Intiator", cycles_total_i/INTERACTION_NUM, cycles_min_i, cycles_max_i);
	printf("%-25s %-15llu %-15llu %-15llu\n", "Responder", cycles_total_r/INTERACTION_NUM, cycles_min_r, cycles_max_r);
    printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (us)", "AVG", "Min", "Max");
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "Intiator", us_total_i, k_cyc_to_us_near64(cycles_min_i), k_cyc_to_us_near64(cycles_max_i));
	printf("%-25s %-15lld  %-15lld  %-15lld \n", "Responder", us_total_r, k_cyc_to_us_near64(cycles_min_r), k_cyc_to_us_near64(cycles_max_r));
	#endif
	#ifdef MEASURE_CLK
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s \n", "time (CLK)", "Intiator", "Responder");
	printf("%-25s AVG:%-15llu & AVG:%-15llu \n", "", clk_total_i/INTERACTION_NUM,clk_total_r/INTERACTION_NUM);
	printf("%-25s MIN:%-15llu & MIN:%-15llu \n", "", clk_min_i, clk_min_r);
	printf("%-25s MAX:%-15llu & MAX:%-15llu \n", "", clk_max_i, clk_max_r);
	printf("---------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s \n", "Elapsed time (ms)", "Initiator",  "Responder");
	printf("%-25s %-15.3f & %-15.4f  \n", "AVG", ((float)clk_total_i*TIME_RATE/CPU_CLK)/INTERACTION_NUM, ((float)clk_total_r*TIME_RATE/CPU_CLK)/INTERACTION_NUM);
	printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (CLK)", "AVG", "Min", "Max");
	printf("%-25s %-15llu %-15llu %-15llu\n", "Intiator", clk_total_i/INTERACTION_NUM, clk_min_i, clk_max_i);
	printf("%-25s %-15llu %-15llu %-15llu\n", "Responder", clk_total_r/INTERACTION_NUM, clk_min_r, clk_max_r);
	printf("----------------------------------------------------------------------\n");
	printf("%-25s %-15s %-15s %-15s\n", "Elapsed time (ms)", "AVG", "Min", "Max");
	printf("%-25s %-15.3f  %-15.4f  %-15.4f \n", "Initiator", ((float)clk_total_i*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_i*TIME_RATE/CPU_CLK, (float)clk_max_i*TIME_RATE/CPU_CLK);
	printf("%-25s %-15.4f  %-15.4f  %-15.4f \n", "Responder", ((float)clk_total_r*TIME_RATE/CPU_CLK)/INTERACTION_NUM, (float)clk_min_r*TIME_RATE/CPU_CLK, (float)clk_max_r*TIME_RATE/CPU_CLK);
    
    #endif
}
#endif