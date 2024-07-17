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
//#include <zephyr/net/coap_client.h>

//#include "edhoc.h"
//#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
//#include "common/crypto_wrapper.h"
//#include <api.h>

#define URI_PATH 11
#define PQ_PROPOSAL_1




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
	/*if (k_sem_take(&my_sem_init, K_MSEC(50)) != 0) {
	}
	else{
		PRINT_MSG("ok\n");
	}	*/


	/*BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);*/
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

	const uint8_t TEST_VEC_NUM = 8;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

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
	
	#endif

   
	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
    
	for (size_t i = 0; i < 100; i++)
	{
			size_t sig_len = 690;
			uint8_t sig[sig_len];
			int i = 0;
			for (i = 0; i < sig_len; ++i) {
				sig[i] = 0;
			}
			uint8_t message[32] = "heeeeeeeelloooooooooooooooooo!";
			//PRINT_ARRAY("sk:",c_i.sk_i.ptr,c_i.sk_i.len);	
			//Testing for sign errors
			int ret = crypto_sign_signature(sig, &sig_len, message, 32, c_i.sk_i.ptr);
			PRINTF("crypto sign signature RET: %d\n",ret);
			PRINTF("sign size: %d\n",sig_len);
			//PRINT_ARRAY("SIGN:",sig,sig_len);

			ret = crypto_sign_verify(sig, sig_len, message, 32, c_i.pk_i.ptr);
			if(ret == 0){
				PRINT_MSG("Verify success!\n");
			}
			else{
				PRINT_MSG("verify fail!\n");
			}
	}
	
	/*#define MSG_LEN 32
	size_t sm_len = 690 + MSG_LEN;
	uint8_t sm[sm_len];
	uint8_t message[MSG_LEN] = "heeeeeeeelloooooooooooooooooo!";


	int ret = crypto_sign(sm, &sm_len, message, MSG_LEN, c_i.sk_i.ptr);
	PRINTF("RET %d\n", ret);
	PRINT_ARRAY("signature:",sm,sm_len);



	uint8_t message2[MSG_LEN];
	size_t msg_len = MSG_LEN;

	ret = crypto_sign_open(message2, &msg_len, sm, sm_len,c_i.pk_i.ptr);
	if(ret == 0){
		PRINT_MSG("Verify success!\n");
	}
	else{
		PRINT_MSG("verify fail!\n");
	}*/
	/*edhoc_initiator_run(&c_i, &cred_r_array, &err_msg, &PRK_out, tx, rx,
			    ead_process);

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
		    oscore_master_salt.len);*/

	//close(sockfd);
	return 0;
}


void main(void)
{
	//int r = internal_main();
	PRINT_MSG("MAIN\n");
	//k_sem_init(&my_sem, 0, 1);
	//k_sem_init(&my_sem_tx, 0, 2);
	//start_coap_client(&sockfd);
    //coap_client_init(&client, NULL);
	//txrx_edhoc(sockfd);
	edhoc_initiator_init();
	

	//coap_client_init(&client, NULL);
	//k_sem_give(&my_sem_init);
	/*if (r != 0) {
		printf("error during initiator run. Error code: %d\n", r);
	}*/
}
/* Create thread for EDHOC */
/*K_THREAD_DEFINE(edhoc_thread, //name
		50008, //stack_size
		edhoc_initiator_init, //entry_function
		NULL, NULL, NULL, //parameter1,parameter2,parameter3
		5, //priority
		0, //options
		20000); //delayz*/