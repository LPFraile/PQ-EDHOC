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
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

extern "C" {
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
}

#include "coap3/coap.h"
//#define USE_IPV4
#define USE_IPV6
#define PQ_PROPOSAL_1
/*comment this out to use PQ keys from the test vectors*/
//#define USE_RANDOM_EPHEMERAL_DH_KEY
uint8_t TEST_VEC_NUM = 7;

#ifdef USE_IPV4
#define COAP_CLIENT_URI "coap://127.0.0.1:5683/edhoc"
#endif

#ifdef USE_IPV6
#define SERVER_ADDR "2001:db8::2"
#define COAP_CLIENT_URI "coap://2001:db8::2:5683/edhoc"
#endif

#define MAX_PAYLOAD_SIZE 5000
#define MAX_BLOCK_SIZE 512

static uint8_t my_buffer[MAX_PAYLOAD_SIZE];
static int my_buffer_len = 0;
static uint8_t my_buffer2[MAX_PAYLOAD_SIZE];
static int my_buffer_len2 = 0;
coap_context_t *ctx = NULL;
coap_endpoint_t *endpoint;
coap_resource_t *resource;
coap_address_t server_addr;


sem_t semaphore;
sem_t semaphore2;
sem_t semaphore_finish;


static void
hnd_post(coap_resource_t *resource, coap_session_t *session, const coap_pdu_t *request,
    const coap_string_t *query, coap_pdu_t *response) {
  	size_t size;
	const uint8_t *data;
	size_t offset;
	size_t total;
	PRINT_MSG("Handle post\n");

	coap_get_data_large(request, &size, &data, &offset, &total);
	PRINT_MSG("large data get it!\n");
	if (size > MAX_PAYLOAD_SIZE) {
		PRINT_MSG("Size biger than max payload\n");
		size = MAX_PAYLOAD_SIZE;
	}
	memcpy(my_buffer, data, size);
	my_buffer_len = size;
	//PRINT_ARRAY("MSG:",my_buffer,my_buffer_len);
	PRINTF("RX MSG size %d\n",my_buffer_len);
    sem_post(&semaphore2);	
    sem_wait(&semaphore);
   
    coap_pdu_set_code(response,COAP_RESPONSE_CODE_CHANGED);
    PRINTF("TX MSG size %d\n",my_buffer_len2);
	//PRINT_ARRAY("MSG:",my_buffer2,my_buffer_len2);
  
    /* Add the MSG2 received in the request payload */
    coap_add_data_large_response(resource, session, request, response, query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                                my_buffer_len2,my_buffer2, NULL, NULL);
}

enum err tx(void* sock,struct byte_array *data)
{
   PRINT_MSG("in TX\n");
   //PRINT_ARRAY("MSG to TX:",data->ptr,data->len);
   memcpy(my_buffer2,data->ptr,data->len);
   my_buffer_len2 = data->len;
   sem_post(&semaphore);
   return ok;
}

enum err rx(void* sock, struct byte_array *data) {
	PRINT_MSG("In RX\n");	
	sem_wait(&semaphore2);
	memcpy(data->ptr,my_buffer,my_buffer_len);
	data->len = my_buffer_len;
	//PRINT_ARRAY("MSG RX:",data->ptr,data->len);
	return ok;
  
} 
/* Function to set up the CoAP server*/
int setup_server(void)
{

    // Initialize CoAP library
	PRINT_MSG("SETUP SERVER\n");
    coap_startup();
    // Create CoAP context
    ctx = coap_new_context(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create CoAP context\n");
        return -1;
    }
    
	coap_context_set_block_mode(ctx,  COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY );
	
	if(coap_context_set_max_block_size(ctx,MAX_BLOCK_SIZE)==1){
		PRINTF("Block size setting to %zu\n",MAX_BLOCK_SIZE);
	}
	else{
		PRINT_MSG("Erros in set max block size\n");
	}

    // Set up server address
    coap_address_init(&server_addr);
	#ifdef USE_IPV4
    server_addr.addr.sin.sin_family = AF_INET;
    server_addr.addr.sin.sin_port = htons(5683); // Standard CoAP port
    server_addr.addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server IPv4 address
	#endif
	#ifdef USE_IPV6
	server_addr.addr.sin6.sin6_family = AF_INET6;
    server_addr.addr.sin6.sin6_port = htons(5683); // Standard CoAP port
    inet_pton(AF_INET6, SERVER_ADDR, &server_addr.addr.sin6.sin6_addr);
    #endif
    // Create CoAP endpoint
    endpoint = coap_new_endpoint(ctx, &server_addr, COAP_PROTO_UDP);
    if (!endpoint) {
        fprintf(stderr, "Failed to create CoAP endpoint\n");
        coap_free_context(ctx);
        return -1;
    }
	
	// Create the CoAP resource
	resource =  coap_resource_init(coap_make_str_const("edhoc"), 0);
	if (!resource) {
		fprintf(stderr, "Cannot create resource\n");
		coap_free_context(ctx);
		return -1;
	}

	// Register the handler for POST requests
	coap_register_handler(resource, COAP_REQUEST_POST, hnd_post);

	// Add the resource to the context
	coap_add_resource(ctx, resource);

	
    return 0;
}


enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

void * edhoc_responder_init(void *arg)
{
	int sockfd;
	uint8_t prk_ex[32];
	uint8_t oscore_secret[16];
	uint8_t oscore_salt[8];
	uint8_t PRK[32];	
	uint8_t err[0];
	byte_array prk_exporter;
	prk_exporter.ptr = prk_ex;
	prk_exporter.len = 32;
	byte_array err_msg;
	err_msg.ptr = err;
	err_msg.len = 1;
	byte_array PRK_out;
	PRK_out.ptr = PRK;
	PRK_out.len = 32;
	byte_array oscore_master_secret;
    oscore_master_secret.ptr = oscore_secret;
	oscore_master_secret.len = 16;

	byte_array oscore_master_salt;
    oscore_master_salt.ptr = oscore_salt;
	oscore_master_salt.len = 8;
	
	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;


	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_r.sock = &sockfd;
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

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	uint32_t seed;
	uint8_t Y[32];
	uint8_t GY[32];
	byte_array Y_random;
	Y_random.ptr = Y;
	Y_random.len = 32;
	byte_array G_Y_random;
	G_Y_random.ptr = GY;
	G_Y_random.len = 32;
	
	c_r.g_y.ptr = G_Y_random.ptr;
	c_r.g_y.len = G_Y_random.len;
	c_r.y.ptr = Y_random.ptr;
	c_r.y.len = Y_random.len;
#endif
#ifdef PQ_PROPOSAL_1
	PRINTF("test vector number: %d\n", vec_num_i+1);
	struct suite suit_in;
	get_suite((enum suite_label)c_r.suites_r.ptr[c_r.suites_r.len - 1],
		      &suit_in);
	uint8_t G_Y[get_kem_cc_len(suit_in.edhoc_ecdh)];
	c_r.g_y.ptr = G_Y;
	c_r.g_y.len = get_kem_cc_len(suit_in.edhoc_ecdh);
	c_r.y.ptr = NULL;
	c_r.y.len = 0;
	PRINTF("test vector number: %d\n", vec_num_i+1);
	PRINTF("INITIATOR SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign)
	PRINTF("responder pk size: %d \n", c_r.pk_r.len);
	PRINTF("responder sk size: %d \n", c_r.sk_r.len);
#endif
	while (1) {
#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
		/*create ephemeral DH keys from seed*/
		/*create a random seed*/
		FILE *fp;
		fp = fopen("/dev/urandom", "r");
		uint64_t seed_len =
			fread((uint8_t *)&seed, 1, sizeof(seed), fp);
		fclose(fp);
		PRINT_ARRAY("seed", (uint8_t *)&seed, seed_len);

		if(ephemeral_dh_key_gen(P256, seed, &Y_random, &G_Y_random)!=ok){
			PRINT_MSG("ephemeral_dh_key_gen return error");
		}
		PRINT_ARRAY("secret ephemeral DH key", c_r.g_y.ptr,
			    c_r.g_y.len);
		PRINT_ARRAY("public ephemeral DH key", c_r.y.ptr, c_r.y.len);
#endif

#ifdef TINYCRYPT
		/* Register RNG function */
		uECC_set_rng(default_CSPRNG);
#endif
	
		edhoc_responder_run(&c_r, &cred_i_array, &err_msg, &PRK_out,
					tx, rx, ead_process);
		PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

		if(prk_out2exporter(SHA_256, &PRK_out, &prk_exporter)!=ok){
			PRINT_MSG("Error in prk_out2exporter");
		}
		PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

		if(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
				   &oscore_master_secret)!=ok){
			PRINT_MSG("Error in edhoc exporter");			
		}
		PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
			    oscore_master_secret.len);

		if(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
				   &oscore_master_salt)!=ok){
			PRINT_MSG("error in second edhoc exporter");		
		}
		PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
			    oscore_master_salt.len);
		sem_post(&semaphore_finish);
		//pthread_exit(0);
	}
	
}
int main()
{
	//while(1){
		PRINT_MSG("on while main\n");
		pthread_t thread1;
		//sem_init(&semaphore, 0, 0);
		coap_set_log_level(LOG_DEBUG);
		pthread_create(&thread1, NULL, edhoc_responder_init, NULL);
		if (setup_server() != 0) {
				fprintf(stderr, "Failed to set up CoAP\n");
				return EXIT_FAILURE;
		}
		// Main loop to handle incoming requests
       while (1) {
        coap_io_process(ctx, COAP_IO_WAIT);
       }

		// Clean up
		PRINT_MSG("GO TO FREE CONTEXTS\n");
		coap_free_context(ctx);
		coap_cleanup();
			//pthread_join(thread1, NULL);
			//sem_wait(&semaphore_finish);
			PRINT_MSG("FINISHING MAIN\n");
		//}
	return 0;
}
