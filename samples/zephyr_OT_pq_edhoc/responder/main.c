/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(coap);

#include <stdio.h>
#include <zephyr/kernel.h>
#include "edhoc.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "coap_utils.h"
#include <openthread/platform/radio.h>
#include <openthread/message.h>
#include <openthread/udp.h>
#include "post.h"
#define POST_URI "post_data"
#define address "ff03::1"

#ifdef USE_SUIT_7
#define MAX_PAYLOAD_SIZE 1500
#undef TEST_X5T_NUM
#define TEST_X5T_NUM 7
#define TEST_X5CHAIN_NUM 8
#define MY_STACK_SIZE 25008
/* size of stack area used by each thread */
#define MAX_MSG_SIZE 3200
#define PQ_PROPOSAL_1
/*KYBER LEVEL 1, DILITHIUM LEVEL 2*/
#elif USE_SUIT_12
#define MAX_PAYLOAD_SIZE 3209
#define TEST_X5T_NUM 11
#define TEST_X5CHAIN_NUM 12
/* size of stack area used by each thread */
#define MY_STACK_SIZE 70000
#define PQ_PROPOSAL_1
/*KYBER LEVEL 1, HAWK LEVEL 2*/
#elif USE_SUIT_14
#define MAX_PAYLOAD_SIZE 1500
#define TEST_X5T_NUM 16
#define TEST_X5CHAIN_NUM 16
/* size of stack area used by each thread */
#define MY_STACK_SIZE 25008
#define PQ_PROPOSAL_1
/*KYBER LEVEL 1, HAETAE LEVEL 2*/
#elif USE_SUIT_15
#define MAX_PAYLOAD_SIZE 2500
#define TEST_X5T_NUM 17
#define TEST_X5CHAIN_NUM 17
/* size of stack area used by each thread */
#define MY_STACK_SIZE 80000
#define PQ_PROPOSAL_1
/*CIPHER SUIT 2 secp256r1 ECDSA* */
#elif USE_SUIT_2
#include <zephyr/random/random.h> // Ensure this is included
#define TEST_X5T_NUM 2
#define TEST_X5CHAIN_NUM 3
// #define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define MY_STACK_SIZE 11000
#define MAX_PAYLOAD_SIZE 800
#define USE_RANDOM_EPHEMERAL_DH_KEY
extern int default_CSPRNG(uint8_t *dest, unsigned int size);
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
	// Zephyr < 3.0 used sys_rand_get. Newer Zephyr uses sys_rand32_get or sys_csrand_get.
	// Let's implement a robust filler using sys_rand32_get which is almost always available.

	// Fill buffer in 4-byte chunks
	uint32_t random_val;
	unsigned int i;

	for (i = 0; i < size / 4; i++) {
		random_val = sys_rand32_get(); // This is standard Zephyr API
		memcpy(dest + (i * 4), &random_val, 4);
	}

	// Fill remaining bytes
	if (size % 4) {
		random_val = sys_rand32_get();
		memcpy(dest + (i * 4), &random_val, size % 4);
	}

	return 1; // TinyCrypt expects non-zero on success (usually 1)
}
#else
#error "Need to define ciphersuit"

#endif

#ifdef USE_X5CHAIN
#define TEST_VEC_NUM TEST_X5CHAIN_NUM
#elif USE_X5T
#define TEST_VEC_NUM TEST_X5T_NUM
#else
#error "need to define x5chain or x5t"
#endif

uint8_t coap_buf_msg[COAP_ENTIRE_MESSAGE_SIZE];
/*struct byte_array {
	uint8_t *buf;
	uint16_t len;
};*/

/**
 * @brief	Initializes sockets for TCP client.
 * @param
 * @retval	error code
 */
//static int start_socket_client(int *sockfd)
//{
/*struct sockaddr_in6 servaddr;
    //const char IPV6_SERVADDR[] = { "::1" };
    const char IPV6_SERVADDR[] = { "2001:db8::2" };
    int r = ipv6_sock_init(SOCK_CLIENT, IPV6_SERVADDR, &servaddr,
                   sizeof(servaddr), sockfd);
    if (r < 0) {
        printf("error during socket initialization (error code: %d)",
               r);
        return -1;
    }*/
//	return ok;
//}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to
 * 		be send over the network. You should implement the transport here over the open TCP socket
 *      and send the data contained in the byte_array struct
 * @param	data pointer to the data that needs to be send
 */
enum err tx(void *sock, struct byte_array *data)
{
	printf("TX RESPONDER-----------------------------\n");
	if (coap_buf_msg == NULL || data->ptr == NULL) {
		PRINTF("coap_buf_msg is NULL\n");
		return -1;
	}

	if (data->len > COAP_ENTIRE_MESSAGE_SIZE) {
		PRINTF("data.len exceeds COAP_ENTIRE_MESSAGE_SIZE\n");
		return -1;
	}

	if (data->len < 0) {
		PRINTF("data.len is negative\n");
		return -1;
	}

	//data->len = strlen((const char *)data->ptr) + 1;
	PRINTF("data->len before memcpy in tx:%d\n\n", data->len);
	/*
	PRINT_ARRAY("server_post_ctx.buf before memcpy in tx start\n", server_post_ctx.buf, 2);
	PRINT_ARRAY("server_post_ctx.buf before memcpy in tx end\n", server_post_ctx.buf + server_post_ctx.len - 2, 2);
	PRINTF("server_post_ctx.len before memcpy in tx:%d\n\n", server_post_ctx.len);
	PRINT_ARRAY("data->buf before memcpy in tx start\n", data->buf, 2);
	PRINT_ARRAY("data->buf before memcpy in tx end\n", data->buf + data->len - 2, 2);
	PRINTF("data->len before memcpy in tx:%d\n\n", data->len);
*/
	memcpy(server_post_ctx.buf, data->ptr, data->len);
	//data->len = strlen((const char *)data->ptr) + 1;
	server_post_ctx.len = data->len;
	/*
	PRINT_ARRAY("server_post_ctx.buf after memcpy in tx start\n", server_post_ctx.buf, 2);
	PRINT_ARRAY("server_post_ctx.buf after memcpy in tx end\n", server_post_ctx.buf + server_post_ctx.len - 2, 2);
	PRINTF("server_post_ctx.len after memcpy in tx:%d\n", server_post_ctx.len);
*/
	printf("give semaphore who wait for tx finish\n");
	k_sem_give(server_post_ctx.post_uedhoc_wait_sem);

	return 0;
}

/**
 * @brief	Callback function called inside the frontend when data needs to
 * 		be received over the network. You should implement the receive data over the open TCP socket,
 *      this should wait until data is received and then fill the byte_array struct with the received data
 * @param	data pointer to the data that needs to be received
 */
enum err rx(void *sock, struct byte_array *data)
{
	int ret = 0;
	PRINTF("RX\n");
	k_sem_reset(server_post_ctx.rx_wait_sem);
	ret = k_sem_take(server_post_ctx.rx_wait_sem, K_FOREVER);
	PRINTF("RX responder receive CoAp POST...\n");
	if (ret == 0) {
		PRINTF("Main: Response received! Continuing.\n");

		memcpy(data->ptr, server_post_ctx.buf, server_post_ctx.len);
		data->len = server_post_ctx.len;

		PRINTF("\n\n\n+=+=+=+=+=+=+=+=+=+=MESSAGE in rx=+=+=+=+=+=+=+=+=+=+\n");
		PRINT_ARRAY("Message start", data->ptr, 2);
		PRINT_ARRAY("Message end", data->ptr + data->len - 2, 2);
		PRINTF("data->len in rx:%d\n", data->len);
		PRINTF("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n\n");

		//server_post_ctx.len = 0;

		return 0;
	}

	return -1;
}

int internal_main(void)
{
	//int32_t s = 30000;
	//printf("sleep for %d msecond after connection in order to have time to start wireshark on bt0\n",
	//       s);
	//k_msleep(s);

	//int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t vec_num_i = TEST_VEC_NUM - 1;

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
	/*cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;*/
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	//get_suite(enum suite_label label, struct suite *suite)
	PRINTF("test vector number: %d\n", vec_num_i + 1);
	struct suite suit_in;
	get_suite((enum suite_label)c_r.suites_r.ptr[c_r.suites_r.len - 1],
		  &suit_in);
	//PRINT_ARRAY("cipher suit:", c_r.suites_r.ptr,c_r.suites_r.len);
	PRINTF("INITIATOR SUIT kem: %d, signature %d\n", suit_in.edhoc_ecdh,
	       suit_in.edhoc_sign)
	PRINTF("responder pk size: %d \n", c_r.pk_r.len);
	PRINTF("responder sk size: %d \n", c_r.sk_r.len);
#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	uint32_t seed;
	BYTE_ARRAY_NEW(Y_random, 32, 32);
	BYTE_ARRAY_NEW(G_Y_random, 32, 32);
	c_r.g_y.ptr = G_Y_random.ptr;
	c_r.g_y.len = G_Y_random.len;
	c_r.y.ptr = Y_random.ptr;
	c_r.y.len = Y_random.len;
#endif
#ifdef PQ_PROPOSAL_1
	PRINT_MSG("PQC ciphersuit selected\n");
	BYTE_ARRAY_NEW(G_Y_ENC, get_kem_cc_len(suit_in.edhoc_ecdh),
		       get_kem_cc_len(suit_in.edhoc_ecdh));
	//BYTE_ARRAY_NEW(PQ_secret_random, get_kem_sk_len(suit_in.edhoc_ecdh), get_kem_sk_len(suit_in.edhoc_ecdh));
	c_r.g_y.ptr = G_Y_ENC.ptr;
	c_r.g_y.len = G_Y_ENC.len;
	c_r.y.ptr = NULL;
	c_r.y.len = 0;
#endif

#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	/*create ephemeral DH keys from seed*/
	/*create a random seed*/
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	uint64_t seed_len = fread((uint8_t *)&seed, 1, sizeof(seed), fp);
	fclose(fp);
	PRINT_MSG("Responder ready to receive EDHOC DH request\n")
	PRINT_ARRAY("seed", (uint8_t *)&seed, seed_len);
	c_r.g_y.len = G_Y_random.len;
	c_r.y.len = Y_random.len;
	TRY(ephemeral_dh_key_gen(P256, seed, &Y_random, &G_Y_random));
	PRINT_ARRAY("public ephemeral key", c_r.g_y.ptr, c_r.g_y.len);
	PRINT_ARRAY("secret ephemeral key", c_r.y.ptr, c_r.y.len);

#endif
#ifdef TINYCRYPT
	/* Register RNG function */
	uECC_set_rng(default_CSPRNG);
#endif
	PRINTF("Responer starting EDHOC run\n");
	//start_socket_client(&sockfd);
	edhoc_responder_run(&c_r, &cred_i_array, &err_msg, &PRK_out, tx, rx,
			    ead_process);
	PRINTF("Responer finished EDHOC run\n");
	/*indicate to the post resource that no more message will be sent*/
	server_post_ctx.no_more_message = 1;
	k_sem_give(server_post_ctx.post_uedhoc_wait_sem);

	PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

	prk_out2exporter(SHA_256, &PRK_out, &prk_exporter);
	PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

	edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
		       &oscore_master_secret);
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
		    oscore_master_secret.len);

	edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
		       &oscore_master_salt);
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
		    oscore_master_salt.len);

	//close(sockfd);
	return 0;
}
void main(void)
{
	int ret;
	printf("Starting CoAP EDHOC Responder Sample\n");
	coap_post_reg_rsc();

	ret = coap_init();
	if (ret) {
		return ret;
	}
	server_post_ctx.no_more_message = 0;
	int r = internal_main();
	if (r != 0) {
		printf("error during initiator run. Error code: %d\n", r);
	}
}
