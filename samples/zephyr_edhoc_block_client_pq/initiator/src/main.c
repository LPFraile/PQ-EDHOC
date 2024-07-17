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
#include <zephyr/net/coap_client.h>

#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"

#define URI_PATH 11
#define PQ_PROPOSAL_1
#define MAX_PAYLOAD_SIZE 2000
static struct coap_client client;
uint8_t my_buffer[MAX_PAYLOAD_SIZE];
uint8_t* ptr = my_buffer;
size_t ptr_len = 0;
size_t my_buffer_len = 0;
int sockfd;
struct k_sem my_sem;
struct k_sem my_sem_tx;
uint8_t my_buffer_tx[MAX_PAYLOAD_SIZE];
size_t my_buffer_tx_len = 0;


/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
static int start_coap_client(int *sockfd)
{
	PRINT_MSG("START COAP CLIENT\n");
	struct sockaddr_in6 servaddr;
	const char IPV6_SERVADDR[] = { "2001:db8::2" };
	int r = ipv6_sock_init(SOCK_CLIENT, IPV6_SERVADDR, &servaddr,
			       sizeof(servaddr), sockfd);
	PRINTF("SOCKFD in startcoap client-%d\n",sockfd);			   
	if (r < 0) {
		printf("error during socket initialization (error code: %d)",
		       r);
		return -1;
	}
	return 0;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}
void response_cb(int16_t code, size_t offset, const uint8_t *payload, size_t len,
                 bool last_block, void *user_data)
{
	PRINT_MSG("Response callback\n");
    if (code >= 0) {
            PRINTF("CoAP response from server %d\n", code);
			if (code == 68){
				PRINT_MSG("ACk with block 2\n");
				memcpy(my_buffer + ptr_len ,payload,len);
				ptr_len = ptr_len + len;

            	if (last_block) {
                	PRINT_MSG("Last packet received\n");
					my_buffer_len = ptr_len;
					PRINT_ARRAY("MSG:",my_buffer,my_buffer_len);
					k_sem_give(&my_sem);
            }
			else if (code  == 95){
				PRINT_MSG("ACK long block go to send next block\n");
			}
		}
			
    } else {
            PRINTF("Error in sending request %d", code);
    }
}
/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be send over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be send
 */
enum err tx(void *sock, struct byte_array *data)
{
	PRINT_MSG("Tx Message\n");

	memcpy(my_buffer_tx,data->ptr,data->len);
	my_buffer_tx_len = data->len;
	PRINT_ARRAY("MSG1-0:",data->ptr,data->len);
	PRINT_ARRAY("MSG1-0:",my_buffer_tx,my_buffer_tx_len);
	k_sem_give(&my_sem_tx);
	return ok;
}
struct coap_client_option options [1];  
struct coap_client_request req = {
		.method = COAP_METHOD_POST,
		.confirmable = true,
		.path = "edhoc",
		.fmt = COAP_CONTENT_FORMAT_TEXT_PLAIN,
		.cb = response_cb,
		.payload = NULL,
		.len = 0,
		.options = options,
		.num_options = 1,

	};
static int txrx_edhoc(int sockfd)
{
	PRINT_MSG("in txrx edhoc\n");
	int ret = 0;
	if (k_sem_take(&my_sem_tx, K_FOREVER) != 0) {
        PRINT_MSG("Input data not available in txrx!\n");
    } else {
		PRINT_MSG("Send the messages\n");
		PRINT_ARRAY("MSG1:",my_buffer_tx,my_buffer_tx_len);
		req.payload = my_buffer_tx;
		req.len = my_buffer_tx_len;
		options[0].code = 60;
		options[0].len = 2;
		options[0].value[0] = (my_buffer_tx_len >> 8) & 0xFF;
		options[0].value[1] = my_buffer_tx_len & 0xFF;
		//PRINTF("value %02X\n",options[0].value[0]);
		//PRINTF("value %02X\n",options[0].value[1]);
		/*options[0].value[0] = 0x03;
		options[0].value[1] = 0x26;*/
		PRINTF("SOCKFDb-%d\n",sockfd);
		ret = coap_client_req(&client, sockfd, NULL, &req, -1);
		if (ret < 0){
			PRINTF("operation fail- %d\n",ret);
		}
	}	
	if (k_sem_take(&my_sem_tx, K_FOREVER) != 0) {
        PRINT_MSG("Input data not available in txrx!\n");
    } else {
		k_sleep(K_MSEC(500));
		PRINT_MSG("Send the messages\n");
		PRINT_ARRAY("MSG3:",my_buffer_tx,my_buffer_tx_len);
		req.payload = my_buffer_tx;
		req.len = my_buffer_tx_len;
		//options[0].value[0] = 0x02;
		//options[0].value[1] = 0xad;
		options[0].value[0] = (my_buffer_tx_len >> 8) & 0xFF;
		options[0].value[1] = my_buffer_tx_len & 0xFF;
		PRINTF("SOCKFD1-%d",sockfd);
		ret = coap_client_req(&client, sockfd, NULL, &req, -1);
		if (ret < 0){
			PRINTF("operation fail- %d\n",ret);
		}
	}	
	return ret;
}
/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be received over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be received
 */
enum err rx(void *sock, struct byte_array *data)
{
	PRINT_MSG("On RX\n");
	if (k_sem_take(&my_sem, K_FOREVER) != 0) {
        PRINT_MSG("Input data not available!");
    } else {
		PRINT_MSG("SET data\n");
		memcpy(data->ptr,my_buffer,my_buffer_len);
		data->len = my_buffer_len;
        /* fetch available data */
    }
	return ok;
}

void edhoc_initiator_init(void)
{
	PRINT_MSG("Init EDHOC\n");
	int r = internal_main();
	if (r != 0) {
		printf("error during initiator run. Error code: %d\n", r);
	}
}


int internal_main(void)
{

	uint8_t prk_ex[32];
	uint8_t oscore_secret[16];
	uint8_t oscore_salt[8];
	uint8_t PRK[32];	
	uint8_t err[0];
	struct byte_array prk_exporter;
	prk_exporter.ptr = prk_ex;
	prk_exporter.len = 32;
	struct byte_array err_msg;
	err_msg.ptr = err;
	err_msg.len = 1;
	struct byte_array PRK_out;
	PRK_out.ptr = PRK;
	PRK_out.len = 32;
	struct byte_array oscore_master_secret;
    oscore_master_secret.ptr = oscore_secret;
	oscore_master_secret.len = 16;

	struct byte_array oscore_master_salt;
    oscore_master_salt.ptr = oscore_salt;
	oscore_master_salt.len = 8;

	/* test vector inputs */
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	const uint8_t TEST_VEC_NUM = 7;
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

    #ifdef PQ_PROPOSAL_1
    /*Ephemeral Key generation for KEMs*/

	struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
		      &suit_in);
	PRINTF("INITIATOR SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign)
	uint8_t PQ_public_random[get_kem_pk_len(suit_in.edhoc_ecdh)];
	uint8_t PQ_secret_random[get_kem_sk_len(suit_in.edhoc_ecdh)];
	//PRINTF("Arrive here 2\n");
	c_i.g_x.ptr = PQ_public_random;
	//c_i.g_x.len = PQ_public_random.len;
	c_i.g_x.len = get_kem_pk_len(suit_in.edhoc_ecdh);
	//PRINTF("Arrive here 3\n");
	c_i.x.ptr = PQ_secret_random;
	c_i.x.len = get_kem_sk_len(suit_in.edhoc_ecdh);

	TRY(ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &c_i.x,&c_i.g_x));

	PRINT_ARRAY("public ephemeral PQ Key", c_i.g_x.ptr, c_i.g_x.len);
	PRINT_ARRAY("secret ephemeral PQ Key", c_i.x.ptr, c_i.x.len);
	#endif

   
	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };


	edhoc_initiator_run(&c_i, &cred_r_array, &err_msg, &PRK_out, tx, rx,
			    ead_process);
    //print("PRK_out", PRK_out.ptr, PRK_out.len);
	print_array( PRK_out.ptr, PRK_out.len);
	//PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

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
	k_thread_abort(k_current_get());

	//close(sockfd);
	return 0;
}


void main(void)
{

	PRINT_MSG("MAIN\n");
	k_sem_init(&my_sem, 0, 1);
	k_sem_init(&my_sem_tx, 0, 2);
	start_coap_client(&sockfd);
    coap_client_init(&client, NULL);
	txrx_edhoc(sockfd);
	//close(sockfd);
	PRINT_MSG("Main finish\n");

}
/* Create thread for EDHOC */
K_THREAD_DEFINE(edhoc_thread, //name
		50008, //stack_size
		edhoc_initiator_init, //entry_function
		NULL, NULL, NULL, //parameter1,parameter2,parameter3
		5, //priority
		0, //options
		20000); //delayz