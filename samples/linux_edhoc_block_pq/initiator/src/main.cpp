/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
}

#include "coap3/coap.h"

/*******************************************************
 * Define coap parameter for retransmisions is use UDP
 * *********************************************************/
/*************************************************************** 
 * Maximum number of retransmisions. If not define by default is 4
 ****************************************************************/
//#define COAP_SESSION_MAX_RET 4 

/*****************************************************************
 * Number of seconds when to expect an ACK or a response to an outstanding 
 * CON message
 * If not define by default is 2 seconds
 ******************************************************************/ 
//#define COAP_SESSION_ACK_TIMEOUT_INT 2  /**< Integer part of fixed point variable */
//#define COAP_SESSION_ACK_TIMEOUT_FRA 0 /**< Fractional part of fixed point variable 1/1000 (3 points) precision */

/*****************************************************************
 * A factor that is used to randomize the wait time before a message
 * is retransmitted to prevent synchronization effects.
 * Default value of ACK_RANDOM_FACTOR is 1.5
******************************************************************/
//#define COAP_SESSION_ACK_RANDOM_FACTOR_INT 1 /**< Integer part of fixed point variable */
//#define COAP_SESSION_ACK_RANDOM_FACTOR_FRA 5 /**< Fractional part of fixed point variable 1/1000 (3 points) precision */


/*Define IPv4 or IPv6*/
#define USE_IPV4
//#define USE_IPV6
#ifdef USE_COAP_BLOCK_SIZE
#define COAP_MAX_BLOCK_SIZE USE_COAP_BLOCK_SIZE
#else
#define COAP_MAX_BLOCK_SIZE 512
#endif
/*is used to set the MTU size (the maximum message size) of the data in a packet, excluding any IP or
TCP/UDP overhead to _mtu_ for the client endpoint's _session_.  The default
MTU is 1152.*/
#define COAP_SESSION_MTU COAP_MAX_BLOCK_SIZE + 80
#if defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 7;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 1500
#elif defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_1) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 8;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 3200
#elif defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_3) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 9;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 1800
#elif defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_3) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 10;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 3500
#elif defined(DILITHIUM_LEVEL_2) && defined(KYBER_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 11;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 3209
#elif defined(DILITHIUM_LEVEL_2) && defined(KYBER_LEVEL_1) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 12;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 7104
#elif defined(FALCON_LEVEL_1) && defined(HQC_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 13;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 7000
#elif defined(FALCON_LEVEL_1) && defined(BIKE_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 14;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 7000
#elif defined(DILITHIUM_LEVEL_2) && defined(BIKE_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 15;
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 7000
#elif defined(DH) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 2;
#define USE_RANDOM_EPHEMERAL_DH_KEY
#define MAX_PAYLOAD_SIZE 800 
#elif defined(DH) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 3;
#define MAX_PAYLOAD_SIZE 800
#define USE_RANDOM_EPHEMERAL_DH_KEY 
#else
#error "you must select a correct test combination in makefile_config.mk file"
#endif

//#define SERVER_ADDR "2001:db8::1"
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "5683"
#define RESOURCE_PATH ".well-known/edhoc"
//#define COAP_CLIENT_URI "coap://coap.me/hello"
#ifdef USE_IPV4
#define COAP_CLIENT_URI "coap://127.0.0.1:5683/edhoc"
#endif

#ifdef USE_IPV6
#define COAP_CLIENT_URI "coap://2001:db8::1/edhoc"
#endif


/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
coap_context_t *ctx = NULL;
coap_session_t *session = NULL;
coap_address_t server_addr;

static uint8_t my_buffer[MAX_PAYLOAD_SIZE];
static int my_buffer_len = 0;
static uint8_t my_buffer_2[MAX_PAYLOAD_SIZE];
static int my_buffer_len_2 = 0;

static coap_response_t
message_handler(coap_session_t *session  COAP_UNUSED,
                const coap_pdu_t *sent,
                const coap_pdu_t *received,
                const coap_mid_t id  COAP_UNUSED)
{
	PRINT_MSG("MEssage handler\n");
    const uint8_t *data;
    size_t len;
    size_t offset;
    size_t total;

    (void)session;
    (void)sent;
    (void)id;
    if (coap_get_data_large(received, &len, &data, &offset, &total)) {
        PRINT_MSG("Get large data:\n");
		//PRINT_ARRAY("MSG",data,len);
		memcpy(my_buffer,data,len);
		my_buffer_len = len;
        if (len + offset == total) {
            printf("\n");
        }
    }
    return COAP_RESPONSE_OK;
}

#ifdef USE_IPV6
int setup(void) {
    // Initialize CoAP library
    coap_startup();

    // Create CoAP context
    ctx = coap_new_context(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create CoAP context\n");
        return -1;
    }
    
	
	coap_context_set_block_mode(ctx,
                              COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY );
	
	if(coap_context_set_max_block_size(ctx,COAP_MAX_BLOCK_SIZE)==1){
		printf("Block size setting to %zu\n",COAP_MAX_BLOCK_SIZE);
	}
	else{
		printf("Erros in set max block size\n");
	}


	// Create CoAP session
    coap_address_init(&server_addr);
    server_addr.addr.sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, SERVER_ADDR, &server_addr.addr.sin6.sin6_addr);
    server_addr.addr.sin6.sin6_port = htons(atoi(SERVER_PORT));
    #ifdef USE_TCP
    session = coap_new_client_session(ctx, NULL, &server_addr, COAP_PROTO_TCP);
    #else
	session = coap_new_client_session(ctx, NULL, &server_addr, COAP_PROTO_UDP);
	#endif
	if (!session) {
        fprintf(stderr, "Failed to create CoAP session\n");
        coap_free_context(ctx);
        return -1;
    }

    return 0;
}
#endif
#ifdef USE_IPV4
int setup(void) {
    // Initialize CoAP library
    coap_startup();

    // Create CoAP context
    ctx = coap_new_context(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create CoAP context\n");
        return -1;
    }

	coap_context_set_block_mode(ctx,
                              COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY );
	
	if(coap_context_set_max_block_size(ctx,COAP_MAX_BLOCK_SIZE)==1){
		printf("Block size setting to %zu\n",COAP_MAX_BLOCK_SIZE);
	}
	else{
		printf("Erros in set max block size\n");
	}

	coap_register_response_handler(ctx, message_handler);
    // Create CoAP session
    coap_address_init(&server_addr);
	#ifdef USE_IPV4
    server_addr.addr.sin.sin_family = AF_INET;
    server_addr.addr.sin.sin_port = htons(5683); // Standard CoAP port
    server_addr.addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server IPv4 address
    #endif
	#ifdef USE_IPV6
	server_addr.addr.sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, SERVER_ADDR, &server_addr.addr.sin6.sin6_addr);
    server_addr.addr.sin6.sin6_port = htons(atoi(SERVER_PORT));
	#endif
	#ifdef USE_TCP
    session = coap_new_client_session(ctx, NULL, &server_addr, COAP_PROTO_TCP);
	#else
	session = coap_new_client_session(ctx, NULL, &server_addr, COAP_PROTO_UDP);
	#endif
	coap_session_set_mtu(session,COAP_SESSION_MTU);
	coap_fixed_point_t value;
	#ifdef COAP_SESSION_MAX_RET
	coap_session_set_max_retransmit(session,COAP_SESSION_MAX_RET);
	#endif
	#ifdef COAP_SESSION_ACK_TIMEOUT
	value.integer_part = COAP_SESSION_ACK_TIMEOUT_INT;
	value.fractional_part = COAP_SESSION_ACK_TIMEOUT_FRA;
	coap_session_set_ack_timeout(session,COAP_SESSION_ACK_TIMEOUT);
	#endif
	#ifdef COAP_SESSION_ACK_RANDOM_FACTOR
	value.integer_part = COAP_SESSION_ACK_RANDOM_FACTOR_INT;
	value.fractional_part = COAP_SESSION_ACK_RANDOM_FACTOR_FRA;
	coap_session_set_ack_random_factor(session,COAP_SESSION_ACK_RANDOM_FACTOR);
	#endif
    if (!session) {
        fprintf(stderr, "Failed to create CoAP session\n");
        coap_free_context(ctx);
        return -1;
    }

    return 0;
}
#endif


enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be send over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be send
 */
int cleanup(){
	//coap_session_release(session);
  	//coap_free_context(ctx);
  	//coap_cleanup();
	return 1;
}

enum err tx(void* sock,struct byte_array *data)
{
	coap_pdu_t *request_pdu = NULL;
    coap_uri_t uri;
	memcpy(my_buffer_2,data->ptr,data->len);
	my_buffer_len_2 = data->len;
   const char *coap_uri = COAP_CLIENT_URI;
	 /* Parse the URI */
	int len = coap_split_uri((const unsigned char *)coap_uri, strlen(coap_uri), &uri);
	if (len != 0) {
		PRINTF("Failed to parse uri %s\n", coap_uri);
	}
  

    const char *path2 = "edhoc";

  // Prepare request PDU
    request_pdu = coap_new_pdu(COAP_MESSAGE_CON, COAP_REQUEST_CODE_POST,session);
    if (!request_pdu) {
        fprintf(stderr, "Failed to create CoAP request PDU\n");
        coap_free_context(ctx);
    }
	// Set URI path and payload
    coap_add_option(request_pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
	coap_add_data_large_request(session,request_pdu,my_buffer_len_2,my_buffer_2,NULL,NULL);	
	

    int result = coap_send(session, request_pdu);
    if (result == COAP_INVALID_TID) {
        fprintf(stderr, "Failed to send request\n");
        cleanup();
		return unexpected_result_from_ext_lib;
    }
	PRINT_MSG("Finished to send long message\n");
	return ok;
}

// Function to receive CoAP response
enum err rx(void* sock, struct byte_array *data) {

  int result = -1;
  while (coap_io_pending(ctx)) {
	uint32_t timeout_ms;
	result = coap_io_process(ctx, timeout_ms);
		memcpy(data->ptr,my_buffer,my_buffer_len);
		data->len = my_buffer_len;

  }
  return ok;
}

int main()
{
	coap_set_log_level(LOG_INFO);
	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_i.sock = &sockfd;
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

#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	uint32_t seed;
	BYTE_ARRAY_NEW(X_random, 32, 32);
	BYTE_ARRAY_NEW(G_X_random, 32, 32);
	
	PRINT_MSG("START EDHOC\n");

	/*create a random seed*/
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	uint64_t seed_len = fread((uint8_t *)&seed, 1, sizeof(seed), fp);
	fclose(fp);
	PRINT_ARRAY("seed", (uint8_t *)&seed, seed_len);

	/*create ephemeral DH keys from seed*/
	TRY(ephemeral_dh_key_gen(P256, seed, &X_random, &G_X_random));
	c_i.g_x.ptr = G_X_random.ptr;
	c_i.g_x.len = G_X_random.len;
	c_i.x.ptr = X_random.ptr;
	c_i.x.len = X_random.len;
	PRINT_ARRAY("secret ephemeral DH key", c_i.g_x.ptr, c_i.g_x.len);
	PRINT_ARRAY("public ephemeral DH key", c_i.x.ptr, c_i.x.len);

#endif

#ifdef PQ_PROPOSAL_1
    /*Ephemeral Key generation for KEMs*/

	struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
		      &suit_in);
	PRINTF("Test vector: %d\n",TEST_VEC_NUM);
	PRINTF("INITIATOR SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign)
	BYTE_ARRAY_NEW(PQ_public_random, get_kem_pk_len(suit_in.edhoc_ecdh), get_kem_pk_len(suit_in.edhoc_ecdh));
	BYTE_ARRAY_NEW(PQ_secret_random, get_kem_sk_len(suit_in.edhoc_ecdh), get_kem_sk_len(suit_in.edhoc_ecdh));
	TRY(ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &PQ_secret_random,&PQ_public_random));

	c_i.g_x.ptr = PQ_public_random.ptr;
	c_i.g_x.len = PQ_public_random.len;
	c_i.x.ptr = PQ_secret_random.ptr;
	c_i.x.len = PQ_secret_random.len;
	PRINTF("public ephemeral PQ Key size: %d\n",c_i.g_x.len);
	PRINTF("secret ephemeral PQ Key size: %d\n",c_i.x.len);
	PRINTF("MAX MSG SIZE: %d\n",edhoc_get_max_msg_size());


#endif


#ifdef TINYCRYPT
	/* Register RNG function */
	uECC_set_rng(default_CSPRNG);
#endif
       // Set up CoAP context and session
    if (setup() != 0) {
        fprintf(stderr, "Failed to set up CoAP\n");
        return EXIT_FAILURE;
    }
	TRY(edhoc_initiator_run(&c_i, &cred_r_array, &err_msg, &PRK_out, tx, rx,
				ead_process));

	PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

	TRY(prk_out2exporter(SHA_256, &PRK_out, &prk_exporter));
	PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
			   &oscore_master_secret));
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
		    oscore_master_secret.len);

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
			   &oscore_master_salt));
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
		    oscore_master_salt.len);
	int result = -1;
	while (coap_io_pending(ctx)) {
		uint32_t timeout_ms;
		result = coap_io_process(ctx, timeout_ms);
  	}

	close(sockfd);
	return 0;
}
