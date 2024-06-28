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
//#include "cantcoap.h"

#include "coap3/coap.h"

#define USE_IPV4
//#define USE_IPV6 
//#define SERVER_ADDR "2001:db8::1"
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "5683"
#define RESOURCE_PATH ".well-known/edhoc"
/*comment this out to use DH keys from the test vectors*/
#define USE_RANDOM_EPHEMERAL_DH_KEY

#define DEFAULT_WAIT_TIME 90
/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
coap_context_t *ctx = NULL;
coap_session_t *session = NULL;
coap_address_t server_addr;

static uint8_t my_buffer[1024];
static int my_buffer_len = 0;

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
		PRINT_ARRAY("MSG",data,len);
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
                              COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
    // Create CoAP session
    coap_address_init(&server_addr);
    server_addr.addr.sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, SERVER_ADDR, &server_addr.addr.sin6.sin6_addr);
    server_addr.addr.sin6.sin6_port = htons(atoi(SERVER_PORT));

    session = coap_new_client_session(ctx, NULL, &server_addr, COAP_PROTO_UDP);
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
                              COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

	coap_register_response_handler(ctx, message_handler);
    // Create CoAP session
    coap_address_init(&server_addr);
    server_addr.addr.sin.sin_family = AF_INET;
    server_addr.addr.sin.sin_port = htons(5683); // Standard CoAP port
    server_addr.addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server IPv4 address

    session = coap_new_client_session(ctx, NULL, &server_addr, COAP_PROTO_UDP);
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
	 // Parse server URI
    if (!coap_split_uri((const uint8_t *)"coap://[" SERVER_ADDR "]:" SERVER_PORT RESOURCE_PATH, strlen(SERVER_ADDR) + strlen(SERVER_PORT) + strlen(RESOURCE_PATH) + 8, &uri)) {
        fprintf(stderr, "Failed to parse URI\n");
        cleanup();
		return unexpected_result_from_ext_lib;
    }
	// Create POST request PDU (confirmable)
    request_pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_POST, 0 /* message id */, coap_session_max_pdu_size(session));
    if (!request_pdu) {
        fprintf(stderr, "Failed to create request PDU\n");
        cleanup();
		return unexpected_result_from_ext_lib;
    }

    // Set URI path and payload
    coap_add_option(request_pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
    coap_add_data(request_pdu,data->len,data->ptr);

    int result = coap_send(session, request_pdu);
    if (result == COAP_INVALID_TID) {
        fprintf(stderr, "Failed to send request\n");
        cleanup();
		return unexpected_result_from_ext_lib;
    }

	return ok;
}

// Function to receive CoAP response
enum err rx(void* sock, struct byte_array *data) {
 /* PRINT_MSG("In RX\n");	*/
  unsigned int wait_seconds = DEFAULT_WAIT_TIME;
  int result = -1;
  unsigned int wait_ms = wait_seconds * 1000;
  printf("RX %d\n",result);
  while (coap_io_pending(ctx)) {
	uint32_t timeout_ms;
	result = coap_io_process(ctx, timeout_ms);
	printf("RESULT %d\n",result);
	if(result>0){
		printf("result is biigger than 0\n");
		memcpy(data->ptr,my_buffer,my_buffer_len);
		data->len = my_buffer_len;
	}
  }
/*
  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();*/
    return ok;
}

int main()
{
	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t TEST_VEC_NUM = 2;
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

#ifdef TINYCRYPT
	/* Register RNG function */
	uECC_set_rng(default_CSPRNG);
#endif
       // Set up CoAP context and session
    if (setup() != 0) {
        fprintf(stderr, "Failed to set up CoAP\n");
        return EXIT_FAILURE;
    }
	//TRY_EXPECT(start_coap_client(&sockfd), 0);
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

	close(sockfd);
	return 0;
}
