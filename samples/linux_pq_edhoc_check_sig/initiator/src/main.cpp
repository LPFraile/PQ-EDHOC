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

extern "C" {
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
}
#include "cantcoap.h"
#ifdef MUPQ 
#include <api.h>
#endif
#define USE_IPV4

#define AUTH_KEY_GEN
#if defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 7;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_7
#elif defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_1) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 8;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_7
#elif defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_3) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 9;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_9
#elif defined(FALCON_LEVEL_1) && defined(KYBER_LEVEL_3) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 10;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_9
#elif defined(DILITHIUM_LEVEL_2) && defined(KYBER_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 11;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_12
#elif defined(DILITHIUM_LEVEL_2) && defined(KYBER_LEVEL_1) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 12;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_12
#elif defined(FALCON_LEVEL_1) && defined(HQC_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 13;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_10
#elif defined(FALCON_LEVEL_1) && defined(BIKE_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 14;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_11
#elif defined(DILITHIUM_LEVEL_2) && defined(BIKE_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 15;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_13
#elif defined(HAWK_LEVEL_1) && defined(KYBER_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 16;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_14
#elif defined(HAWK_LEVEL_1) && defined(KIBER_LEVEL_1) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 16;
#define PQ_PROPOSAL_1
#define USE_SUITE SUITE_14
#elif defined(HAETAE_LEVEL_2) && defined(KYBER_LEVEL_1) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 17;
#define USE_SUITE SUITE_15
#define PQ_PROPOSAL_1
#elif defined(HAETAE_LEVEL_2) && defined(KIBER_LEVEL_1) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 17;
#define USE_SUITE SUITE_15
#define PQ_PROPOSAL_1
#elif defined(DH) && !defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 2;
#define USE_RANDOM_EPHEMERAL_DH_KEY 
#elif defined(DH) && defined(USE_X5CHAIN)
uint8_t TEST_VEC_NUM = 3;
#define USE_RANDOM_EPHEMERAL_DH_KEY 
#else
#error "you must select a correct test combination in makefile_config.mk file"
#endif


CoapPDU *txPDU = new CoapPDU();

char buffer[MAXLINE];
CoapPDU *rxPDU;

#ifdef USE_IPV6
struct sockaddr_in6 client_addr;
#endif
#ifdef USE_IPV4
struct sockaddr_in client_addr;
#endif
socklen_t client_addr_len;

/**
 * @brief	Initializes socket for CoAP server.
 * @param	
 * @retval	error code
 */
static int start_coap_server(int *sockfd)
{
	int err;
#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	//struct sockaddr_in client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV4_SERVADDR[] = { "0.0.0.0" };
	//const char IPV4_SERVADDR[] = { "192.168.43.63" };
	err = sock_init(SOCK_SERVER, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
#ifdef USE_IPV6
	struct sockaddr_in6 servaddr;
	//struct sockaddr_in6 client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV6_SERVADDR[] = { "2001:db8::2" };
	err = sock_init(SOCK_SERVER, IPV6_SERVADDR, IPv6, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif

	return 0;
}
/**
 * @brief	Sends CoAP packet over network.
 * @param	pdu pointer to CoAP packet
 * @retval	error code
 */
static int send_coap_reply(void *sock, CoapPDU *pdu)
{
	int r;

	r = sendto(*((int *)sock), pdu->getPDUPointer(), pdu->getPDULength(), 0,
		   (struct sockaddr *)&client_addr, client_addr_len);
	if (r < 0) {
		printf("Error: failed to send reply (Code: %d, ErrNo: %d)\n", r,
		       errno);
		return r;
	}

	printf("CoAP reply sent!\n");
	return 0;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

enum err tx(void *sock, struct byte_array *data)
{
	txPDU->setCode(CoapPDU::COAP_CHANGED);
	txPDU->setPayload(data->ptr, data->len);
	send_coap_reply(sock, txPDU);
	return ok;
}

enum err rx(void *sock, struct byte_array *data)
{
	int n;

	/* receive */
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));

	n = recvfrom(*((int *)sock), (char *)buffer, sizeof(buffer), 0,
		     (struct sockaddr *)&client_addr, &client_addr_len);
	if (n < 0) {
		printf("recv error");
	}

	rxPDU = new CoapPDU((uint8_t *)buffer, n);

	if (rxPDU->validate()) {
		rxPDU->printHuman();
	}

	PRINT_ARRAY("CoAP message", rxPDU->getPayloadPointer(),
		    rxPDU->getPayloadLength());

	uint32_t payload_len = rxPDU->getPayloadLength();
	if (data->len >= payload_len) {
		memcpy(data->ptr, rxPDU->getPayloadPointer(), payload_len);
		data->len = payload_len;
	} else {
		printf("insufficient space in buffer");
	}

	txPDU->reset();
	txPDU->setVersion(rxPDU->getVersion());
	txPDU->setMessageID(rxPDU->getMessageID());
	txPDU->setToken(rxPDU->getTokenPointer(), rxPDU->getTokenLength());

	if (rxPDU->getType() == CoapPDU::COAP_CONFIRMABLE) {
		txPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
	} else {
		txPDU->setType(CoapPDU::COAP_NON_CONFIRMABLE);
	}

	delete rxPDU;
	return ok;
}

int main()
{
	PRINT_MSG("Signature thread started!\n");
	enum err r;
	struct suite suit_in;
    volatile uint32_t clock_start;
	volatile uint32_t clock_end;
	struct edhoc_initiator_context c_i;
	#ifdef AUTH_KEY_GEN
	get_suite(USE_SUITE,&suit_in);
	/*	uint8_t SK[CRYPTO_SECRETKEYBYTES];
		uint8_t PK[CRYPTO_PUBLICKEYBYTES];
		c_i.sk_i.ptr = SK;
		c_i.sk_i.len = CRYPTO_SECRETKEYBYTES;
		c_i.pk_i.ptr = PK;
		c_i.pk_i.len = CRYPTO_PUBLICKEYBYTES;
	printf("Sk size:%d\n",CRYPTO_SECRETKEYBYTES);
	printf("Pk size:%d\n",CRYPTO_PUBLICKEYBYTES);
	printf("Sig size:%d\n",CRYPTO_BYTES);*/
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	c_i.sk_i.ptr = SK;
	c_i.sk_i.len = get_sk_len(suit_in.edhoc_sign);
	c_i.pk_i.ptr = PK;
	c_i.pk_i.len = get_pk_len(suit_in.edhoc_sign);
	printf("Sk size:%d\n",get_sk_len(suit_in.edhoc_sign));
	printf("Pk size:%d\n", get_pk_len(suit_in.edhoc_sign));
	printf("Sig size:%d\n",get_signature_len(suit_in.edhoc_sign));	
	r = static_signature_key_gen(suit_in.edhoc_sign,&c_i.sk_i,&c_i.pk_i);
		if (r != ok) {
		printf("An error has occurred. Error code: %d\n", r);
		return r;
	}
	#else

    int vec_num_i = TEST_VEC_NUM-1;
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

	/*cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
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
*/
	//struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
				&suit_in);


	#endif
	PRINT_ARRAY("pk",c_i.pk_i.ptr,c_i.pk_i.len);
	PRINT_ARRAY("sk",c_i.sk_i.ptr,c_i.sk_i.len);
				  
	PRINTF("SUIT Signature: %d \n",suit_in.edhoc_sign);
 
	/*uint8_t SIGN1[CRYPTO_BYTES];
	struct byte_array sig1;
	sig1.ptr = SIGN1;
	sig1.len = CRYPTO_BYTES;*/
		uint8_t SIGN1[get_signature_len(suit_in.edhoc_sign)];
	struct byte_array sig1;
	sig1.ptr = SIGN1;
	sig1.len = get_signature_len(suit_in.edhoc_sign);

    PRINTF("Signature len: %d\n",sig1.len);
	//uint8_t message[SIG_STRUCT_SIZE];

	//sys_rand_get(message, sizeof(message));
	uint8_t message[10]= "Hello!!!";
	PRINT_ARRAY("MSG in:",message,10);


	struct byte_array msg;
	msg.ptr = message;
	msg.len = 10;
	//msg.len = SIG_STRUCT_SIZE;
	//printf("MESSGAE to SIGN size:%d",msg.len);
	//print_array(msg.ptr,msg.len);
	
	PRINT_MSG("Before signature\n");

	r = sign_signature(suit_in.edhoc_sign,&c_i.sk_i, &msg, sig1.ptr, &sig1.len);
	if (r != ok) {
		printf("An error has occurred. Error code: %d\n", r);
		return r;
	}else{
		printf("signature success\n");
	}

	r = sign_verify(suit_in.edhoc_sign, &c_i.pk_i, &msg, &sig1);
	if (r != ok) {
		printf("An error has occurred in sign verify. Error code: %d\n", r);
		//return r;
	}else{
		printf("signature verify success\n");
	}
	
	return 0;
}
