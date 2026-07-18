/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"
#include "edhoc_internal.h"

#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/messages.h"
#include "edhoc/okm.h"
#include "edhoc/plaintext.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/suites.h"
#include "edhoc/th.h"
#include "edhoc/txrx_wrapper.h"
#include "edhoc/ciphertext.h"
#include "edhoc/suites.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#ifdef KEM_AUTH
#include "cbor/edhoc_decode_message_1.h"
#include "cbor/edhoc_encode_message_2.h"
//#include "cbor/edhoc_decode_message_1_kem.h"
//#include "cbor/edhoc_encode_message_2_kem.h"
#include "cbor/edhoc_decode_message_3_kem.h"
#include "cbor/edhoc_encode_message_4_kem.h"
#include "cbor/edhoc_decode_message_5_kem.h"
#else
#include "cbor/edhoc_decode_message_1.h"
#include "cbor/edhoc_encode_message_2.h"
#include "cbor/edhoc_decode_message_3.h"
#endif

#define CBOR_UINT_SINGLE_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_UINT_MULTI_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_BSTR_TYPE_MIN_VALUE (0x40)
#define CBOR_BSTR_TYPE_MAX_VALUE (0x57)

#ifdef KEM_AUTH
/** 
 * @brief   			Parses message 2.
 * @param c 			Initiator context.
 * @param[in] msg 		Message. 
 * @param[out] cc		cc KEM cipher text.
 * @param[out] ciphertext	Ciphertext .
 * @retval			Ok or error code.
 */
/*Now we use this for KEM too may we change name from msg2_parse to just msg_parse*/
static inline enum err msg_parse(struct byte_array *msg, struct byte_array *cc,
				 struct byte_array *ciphertext)
{
	BYTE_ARRAY_NEW(cc_ciphertext, CC_CIPHERTEXT, CC_CIPHERTEXT);
	TRY(decode_bstr(msg, &cc_ciphertext));

	TRY(_memcpy_s(cc->ptr, cc->len, cc_ciphertext.ptr, cc->len));
	PRINT_ARRAY("cc", cc->ptr, cc->len);

	TRY(_memcpy_s(ciphertext->ptr, ciphertext->len,
		      cc_ciphertext.ptr + cc->len,
		      cc_ciphertext.len - cc->len));
	ciphertext->len = cc_ciphertext.len - cc->len;
	PRINT_ARRAY("ciphertext", ciphertext->ptr, ciphertext->len);
	return ok;
}

/**
 * @brief   			Encodes message .
 * @param[in] ct 		Public ephemeral DH key of the responder. 
 * @param[in] ciphertext 	The ciphertext.
 * @param[out] msg 		The encoded message.
 * @retval  			Ok or error code.
 */

static inline enum err msg_encode(const struct byte_array *ct,
				  const struct byte_array *ciphertext,
				  struct byte_array *msg)
{
	PRINT_ARRAY("ct", ct->ptr, ct->len);
	PRINT_ARRAY("ciphertext", ciphertext->ptr, ciphertext->len);
	PRINTF("ct len: %d, ciphertext len: %d, CC_CIPHERTEXT: %d\n", ct->len, ciphertext->len, CC_CIPHERTEXT);
	BYTE_ARRAY_NEW(ct_ciphertext, CC_CIPHERTEXT, ct->len + ciphertext->len);
	memcpy(ct_ciphertext.ptr, ct->ptr, ct->len);
	memcpy(ct_ciphertext.ptr + ct->len, ciphertext->ptr, ciphertext->len);
	TRY(encode_bstr(&ct_ciphertext, msg));

	PRINT_ARRAY("message (CBOR Sequence)", msg->ptr, msg->len);
	return ok;
}
#endif
/**
 * @brief   			Parses message 1.
 * @param[in] msg1 		Message 1.
 * @param[out] method 		EDHOC method.
 * @param[out] suites_i 	Cipher suites suported by the initiator
 * @param[out] g_x 		Public ephemeral key of the initiator.
 * @param[out] c_i 		Connection identifier of the initiator.
 * @param[out] ead1 		External authorized data 1.
 * @retval 			Ok or error code.
 */
static inline enum err
msg1_parse(struct byte_array *msg1, enum method_type *method,
	   struct byte_array *suites_i, struct byte_array *g_x,
	   struct byte_array *c_i, struct byte_array *ead1)
{
	uint32_t i;
	struct message_1 m;
	size_t decode_len = 0;
	PRINT_ARRAY("msg1 ", msg1->ptr, msg1->len);
	TRY_EXPECT(cbor_decode_message_1(msg1->ptr, msg1->len, &m, &decode_len),
		   0);
	PRINT_MSG("decoded msg1\n");
	/*METHOD*/
	if ((m.message_1_METHOD > INITIATOR_KEM_RESPONDER_KEM) ||
	    (m.message_1_METHOD < INITIATOR_SK_RESPONDER_SK)) {
		PRINT_MSG("wrong parameters\n");
		return wrong_parameter;
	}

	*method = (enum method_type)m.message_1_METHOD;
	PRINTF("msg1 METHOD: %d\n", (int)*method);

	/*SUITES_I*/
	if (m.message_1_SUITES_I_choice == message_1_SUITES_I_int_c) {
		/*the initiator supports only one suite*/
		suites_i->ptr[0] = (uint8_t)m.message_1_SUITES_I_int;
		suites_i->len = 1;
	} else {
		if (0 == m.SUITES_I_suite_l_suite_count) {
			return suites_i_list_empty;
		}

		/*the initiator supports more than one suite*/
		if (m.SUITES_I_suite_l_suite_count > suites_i->len) {
			return suites_i_list_to_long;
		}

		for (i = 0; i < m.SUITES_I_suite_l_suite_count; i++) {
			suites_i->ptr[i] = (uint8_t)m.SUITES_I_suite_l_suite[i];
		}
		suites_i->len = (uint32_t)m.SUITES_I_suite_l_suite_count;
	}
	PRINT_ARRAY("msg1 SUITES_I", suites_i->ptr, suites_i->len);

	/*G_X*/
	PRINTF("g_x len %d\n", g_x->len);
	PRINTF("g_x len message 1 %d\n", (uint32_t)m.message_1_G_X.len);
	TRY(_memcpy_s(g_x->ptr, g_x->len, m.message_1_G_X.value,
		      (uint32_t)m.message_1_G_X.len));
	g_x->len = (uint32_t)m.message_1_G_X.len;
	PRINT_ARRAY("msg1 G_X", g_x->ptr, g_x->len);

	/*C_I*/
	if (m.message_1_C_I_choice == message_1_C_I_int_c) {
		c_i->ptr[0] = (uint8_t)m.message_1_C_I_int;
		c_i->len = 1;
	} else {
		TRY(_memcpy_s(c_i->ptr, c_i->len, m.message_1_C_I_bstr.value,
			      (uint32_t)m.message_1_C_I_bstr.len));
		c_i->len = (uint32_t)m.message_1_C_I_bstr.len;
	}
	PRINT_ARRAY("msg1 C_I_raw", c_i->ptr, c_i->len);

	/*ead_1*/
	if (m.message_1_ead_1_present) {
		TRY(_memcpy_s(ead1->ptr, ead1->len, m.message_1_ead_1.value,
			      (uint32_t)m.message_1_ead_1.len));
		ead1->len = (uint32_t)m.message_1_ead_1.len;
		PRINT_ARRAY("msg1 ead_1", ead1->ptr, ead1->len);
	}
	return ok;
}

/**
 * @brief   			Checks if the selected cipher suite 
 * 				(the first in the list received from the 
 * 				initiator) is supported.
 * @param selected 		The selected suite.
 * @param[in] suites_r 		The list of suported cipher suites.
 * @retval  			True if supported.
 */
static inline bool selected_suite_is_supported(uint8_t selected,
					       struct byte_array *suites_r)
{
	for (uint32_t i = 0; i < suites_r->len; i++) {
		if (suites_r->ptr[i] == selected)
			PRINTF("Suite %d will be used in this EDHOC run.\n",
			       selected);
		return true;
	}
	return false;
}

/**
 * @brief   			Encodes message 2.
 * @param[in] g_y 		Public ephemeral DH key of the responder. 
 * @param[in] c_r 		Connection identifier of the responder.
 * @param[in] ciphertext_2 	The ciphertext.
 * @param[out] msg2 		The encoded message.
 * @retval  			Ok or error code.
 */
static inline enum err msg2_encode(const struct byte_array *g_y,
				   struct byte_array *c_r,
				   const struct byte_array *ciphertext_2,
				   struct byte_array *msg2)
{
	BYTE_ARRAY_NEW(g_y_ciphertext_2, G_Y_CIPHERTEXT_2,
		       g_y->len + ciphertext_2->len);

	memcpy(g_y_ciphertext_2.ptr, g_y->ptr, g_y->len);
	memcpy(g_y_ciphertext_2.ptr + g_y->len, ciphertext_2->ptr,
	       ciphertext_2->len);

	TRY(encode_bstr(&g_y_ciphertext_2, msg2));

	PRINT_ARRAY("message_2 (CBOR Sequence)", msg2->ptr, msg2->len);
	return ok;
}

enum err msg2_gen(struct edhoc_responder_context *c, struct runtime_context *rc,
		  struct byte_array *c_i)
{
	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	enum method_type method = INITIATOR_SK_RESPONDER_SK;
	BYTE_ARRAY_NEW(suites_i, SUITES_I_SIZE, SUITES_I_SIZE);
	BYTE_ARRAY_NEW(g_x, G_X_SIZE, G_X_SIZE);

	TRY(msg1_parse(&rc->msg, &method, &suites_i, &g_x, c_i, &rc->ead));

	// TODO this may be a vulnerability in case suites_i.len is zero
	if (!(selected_suite_is_supported(suites_i.ptr[suites_i.len - 1],
					  &c->suites_r))) {
		// TODO implement here the sending of an error message
		return error_message_sent;
	}
	/*Add it to exted KEN-based*/
	rc->method = method;
	/*get cipher suite*/
	TRY(get_suite((enum suite_label)suites_i.ptr[suites_i.len - 1],
		      &rc->suite));

	bool static_dh_r;
	authentication_type_get(method, &rc->static_dh_i, &static_dh_r);
	PRINTF("method: %d", method);
	/******************* create and send message 2*************************/

	BYTE_ARRAY_NEW(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);

	if ((suites_i.ptr[suites_i.len - 1] >= SUITE_7) &&
	    (suites_i.ptr[suites_i.len - 1] <= SUITE_16)) {
		/* 	PQ Proposal 1 - key generation with KEMs
		*	Encapsulate the ephemeral key (in g_x) enc(ephpk)->(ss,c) ( enc(g_x)->(g_xy,g_y))
		*   Set the g_y with the ciphertex message c   
		*/
		PRINT_MSG("PQ KEM encapsulation\n");
#if defined(PQM4) || defined(LIBOQS) || defined(PQCLEAN)
		PRINT_ARRAY("PQ DEV - g_x ", g_x.ptr, g_x.len);
		PRINTF("cc size: %d\n", c->g_y.len);
		PRINTF("ss size: %d\n", g_xy.len);
		TRY(kem_encapsulate(rc->suite.edhoc_ecdh, &g_x, &c->g_y,
				    &g_xy));
		PRINTF("Encapsulate correct\n");
		PRINT_ARRAY("G_XY (PQ SS)", g_xy.ptr, g_xy.len);
		PRINT_ARRAY("G_Y (PQ CC)", c->g_y.ptr, c->g_y.len);
#else
		PRINT_MSG("Need to select PQ crypo");
		return -1;
#endif
	} else {
		/*calculate the DH shared secret*/
		PRINT_ARRAY("y ", c->y.ptr, c->y.len);
		PRINT_ARRAY("gx ", g_x.ptr, g_x.len);
		TRY(shared_secret_derive(rc->suite.edhoc_ecdh, &c->y, &g_x,
					 g_xy.ptr));
		PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);
	}

	//BYTE_ARRAY_NEW(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));
	rc->th2.len = HASH_SIZE;
	rc->th2.ptr = (uint8_t *)rc->th2_buf;
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	//TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &c->g_y, &th2));
	TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &c->g_y,
			  &rc->th2));

	BYTE_ARRAY_NEW(PRK_2e, PRK_SIZE, PRK_SIZE);
	//TRY(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	TRY(hkdf_extract(rc->suite.edhoc_hash, &rc->th2, &g_xy, PRK_2e.ptr));
	PRINT_ARRAY("PRK_2e", PRK_2e.ptr, PRK_2e.len);

#ifndef KEM_AUTH
	/*derive prk_3e2m*/
	TRY(prk_derive(static_dh_r, rc->suite, SALT_3e2m, &rc, &PRK_2e, &g_x,
		       &c->r, rc->prk_3e2m.ptr));
	PRINT_ARRAY("prk_3e2m", rc->prk_3e2m.ptr, rc->prk_3e2m.len);

	/*compute signature_or_MAC_2*/
	PRINTF("Signature len %d - %d\n", SIGNATURE_SIZE,
	       get_signature_len(rc->suite.edhoc_sign));
	if (get_signature_len(rc->suite.edhoc_sign) > SIGNATURE_SIZE) {
		//printf("Set correctly the suits in the external makefile_config.mk\n");
		//return -1;
	}
	BYTE_ARRAY_NEW(sign_or_mac_2, SIGNATURE_SIZE,
		       get_signature_len(rc->suite.edhoc_sign));
	PRINTF("Signature len %d - %d\n", SIGNATURE_SIZE,
	       get_signature_len(rc->suite.edhoc_sign));		   
	TRY(signature_or_mac(GENERATE, static_dh_r, &rc->suite, &c->sk_r,
			     &c->pk_r, &rc->prk_3e2m, &c->c_r, &rc->th2,
			     &c->id_cred_r, &c->cred_r, &c->ead_2, MAC_2,
			     &sign_or_mac_2));
	/*compute ciphertext_2*/

	BYTE_ARRAY_NEW(plaintext_2, PLAINTEXT2_SIZE,
		       AS_BSTR_SIZE(c->c_r.len) + c->id_cred_r.len +
			       AS_BSTR_SIZE(sign_or_mac_2.len) + c->ead_2.len);
	BYTE_ARRAY_NEW(ciphertext_2, CIPHERTEXT2_SIZE, plaintext_2.len);
    
	TRY(ciphertext_gen(CIPHERTEXT2, &rc->suite, &c->c_r, &c->id_cred_r,
			   &sign_or_mac_2, &c->ead_2, &PRK_2e, &rc->th2,
			   &ciphertext_2, &plaintext_2));
#else
	/*Keep on runtime contetx the prk_2e*/
	rc->prk_2e.len = PRK_2e.len;
	rc->prk_2e.ptr = (uint8_t *)rc->prk_2e_buf;
	TRY(_memcpy_s(rc->prk_2e.ptr, rc->prk_2e.len, PRK_2e.ptr, PRK_2e.len));
	PRINT_ARRAY("prk_2e", rc->prk_2e.ptr, rc->prk_2e.len);
	/*BYTE_ARRAY_NEW(plaintext_2, PLAINTEXT2_SIZE,
		       AS_BSTR_SIZE(c->c_r.len) + c->id_cred_r.len +
			       c->ead_2.len);*/
	rc->plaintext_2.len = PLAINTEXT2_SIZE;
	rc->plaintext_2.ptr = (uint8_t *)rc->plaintext_2_buf;	
	BYTE_ARRAY_NEW(ciphertext_2, CIPHERTEXT2_SIZE, rc->plaintext_2.len);
	//PRINT_ARRAY("CIPHERTEXT_2", ciphertext_2.ptr, ciphertext_2.len);
	//PRINT_ARRAY("PLAINTEXT_2", rc->plaintext_2.ptr, rc->plaintext_2.len);
	PRINT_ARRAY("C_R", c->c_r.ptr, c->c_r.len);
	PRINT_ARRAY("ID_CRED_R", c->id_cred_r.ptr, c->id_cred_r.len);
	PRINT_ARRAY("EAD_2", c->ead_2.ptr, c->ead_2.len);
	TRY(ciphertext_gen(CIPHERTEXT2, &rc->suite, &c->c_r, &c->id_cred_r,
			   NULL, &c->ead_2, &PRK_2e, &rc->th2, &ciphertext_2,
			   &rc->plaintext_2));
#endif
	/* Clear the message buffer. */
	memset(rc->msg.ptr, 0, rc->msg.len);
	rc->msg.len = sizeof(rc->msg_buf);
	/*message 2 create*/
	TRY(msg2_encode(&c->g_y, &c->c_r, &ciphertext_2, &rc->msg));
	/*TRY(th34_calculate(rc->suite.edhoc_hash, &rc->th2, &plaintext_2,
			   &c->cred_r, &rc->th3));
     */
	#ifndef KEM_AUTH
	TRY(th34_calculate(rc->method, rc->suite.edhoc_hash, &rc->th2, &plaintext_2,
			   &c->cred_r,&NULL_ARRAY, &rc->th3));
	#endif
	return ok;
}

enum err msg3_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct cred_array *cred_i_array,
		      struct byte_array *prk_out,
		    struct byte_array *initiator_pk)
				
{
	BYTE_ARRAY_NEW(ctxt3, CIPHERTEXT3_SIZE, rc->msg.len);
#ifndef KEM_AUTH
	TRY(decode_bstr(&rc->msg, &ctxt3));
#else
	rc->cc_R.len = get_kem_cc_len(rc->suite.edhoc_ecdh);
	rc->cc_R.ptr = (uint8_t *)rc->cc_R_buf;
	rc->ss_R.len = get_kem_ss_len(rc->suite.edhoc_ecdh);
	rc->ss_R.ptr = (uint8_t *)rc->ss_R_buf;
	TRY(msg_parse(&rc->msg, &rc->cc_R, &ctxt3));
	PRINT_ARRAY("cc_R (PQ CC)", rc->cc_R.ptr, rc->cc_R.len);
	PRINT_ARRAY("pk_R (PQ PK)", c->g_r.ptr, c->g_r.len);
	PRINT_ARRAY("sk_R (PQ SK)", c->r.ptr, c->r.len);
	TRY(kem_decapsulate(rc->suite.edhoc_ecdh, &rc->cc_R, &c->r, &rc->ss_R));
	PRINT_ARRAY("SS_R (PQ SS) ", rc->ss_R.ptr, rc->ss_R.len);

	TRY(th34_calculate(rc->method, rc->suite.edhoc_hash, &rc->th2, &rc->plaintext_2,
			   &c->cred_r,&rc->cc_R, &rc->th3));

	bool static_dh_r;
	authentication_type_get(rc->method, &rc->static_dh_i, &static_dh_r);
	PRINTF("method: %d", rc->method);
	/*derive prk_3e2m*/
	rc->prk_3e2m.len = PRK_SIZE;
	rc->prk_3e2m.ptr = (uint8_t *)rc->prk_3e2m_buf;
	TRY(prk_derive_KEM(1, rc->suite, SALT_3e2m, &rc->th2, &rc->prk_2e,
			   &rc->ss_R, rc->prk_3e2m.ptr));
	PRINT_ARRAY("prk_3e2m", rc->prk_3e2m.ptr, rc->prk_3e2m.len);

#endif
	PRINT_ARRAY("CIPHERTEXT_3", ctxt3.ptr, ctxt3.len);

	//BYTE_ARRAY_NEW(id_cred_i, ID_CRED_I_SIZE, ID_CRED_I_SIZE);
	rc->id_cred_i.len = ID_CRED_I_SIZE;
	rc->id_cred_i.ptr = (uint8_t *)rc->id_cred_i_buf;
	//BYTE_ARRAY_NEW(cred_i, CRED_I_SIZE, CRED_I_SIZE

#ifndef KEM_AUTH
	BYTE_ARRAY_NEW(sign_or_mac, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);
#endif
	PRINTF("PLAINTEXT3_SIZE: %d\n", PLAINTEXT3_SIZE);
	PRINTF("ctxt3.len: %d\n", ctxt3.len);
#if defined(_WIN32)
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + 16, // 16 is max aead mac length
		       ctxt3.len);
#else
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ctxt3.len);
#endif

#ifndef KEM_AUTH
	TRY(ciphertext_decrypt_split(CIPHERTEXT3, &rc->suite, NULL, &rc->id_cred_i,
				     &sign_or_mac, &rc->ead, &rc->prk_3e2m,
				     &rc->th3, &ctxt3, &ptxt3));
#else
	TRY(ciphertext_decrypt_split(CIPHERTEXT3, &rc->suite, NULL,
				     &rc->id_cred_i, NULL, &rc->ead, &rc->prk_3e2m,
				     &rc->th3, &ctxt3, &ptxt3));
#endif
	/*check the authenticity of the initiator*/
	BYTE_ARRAY_NEW(cred_i, CRED_I_SIZE, CRED_I_SIZE);
	BYTE_ARRAY_NEW(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_i, G_I_SIZE, G_I_SIZE);

	TRY(retrieve_cred(rc->static_dh_i, cred_i_array, &rc->id_cred_i, &cred_i,
			  &pk, &g_i));

	/* Export public key. */
	if ((NULL != initiator_pk) && (NULL != initiator_pk->ptr)) {
		_memcpy_s(initiator_pk->ptr, initiator_pk->len, pk.ptr, pk.len);
		initiator_pk->len = pk.len;
	}

	/*derive prk_4e3m*/
	#ifndef KEM_AUTH
	TRY(prk_derive(rc->static_dh_i, rc->suite, SALT_4e3m, &rc->th3,
		       &rc->prk_3e2m, &g_i, &c->y, rc->prk_4e3m.ptr));
	#else
	rc->cc_I.len = get_kem_cc_len(rc->suite.edhoc_ecdh);
	rc->cc_I.ptr = (uint8_t *)rc->cc_I_buf;
	rc->ss_I.len = get_kem_ss_len(rc->suite.edhoc_ecdh);
	rc->ss_I.ptr = (uint8_t *)rc->ss_I_buf;
	PRINT_ARRAY("G_I (KEM-PK_I)", g_i.ptr, g_i.len);
	TRY(kem_encapsulate(rc->suite.edhoc_ecdh, &g_i, &rc->cc_I, &rc->ss_I));
	PRINT_ARRAY("CC_I", rc->cc_I.ptr, rc->cc_I.len);
	PRINT_ARRAY("SS_I", rc->ss_I.ptr, rc->ss_I.len);
	TRY(th34_calculate(rc->method, rc->suite.edhoc_hash, &rc->th3, &ptxt3,
			   &cred_i,&rc->cc_I, &rc->th4));
	PRINT_ARRAY("TH4", rc->th4.ptr, rc->th4.len);
	PRINT_ARRAY("PRK_3e2m", rc->prk_3e2m.ptr, rc->prk_3e2m.len);
	TRY(prk_derive_KEM(rc->static_dh_i, rc->suite, SALT_4e3m, &rc->th4, &rc->prk_3e2m, &rc->ss_I, rc->prk_4e3m.ptr));
	#endif

	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);

#ifndef KEM_AUTH
	TRY(signature_or_mac(VERIFY, rc->static_dh_i, &rc->suite, NULL, &pk,
			     &rc->prk_4e3m, &NULL_ARRAY, &rc->th3, &rc->id_cred_i,
			     &cred_i, &rc->ead, MAC_3, &sign_or_mac));
	TRY(th34_calculate(rc->method, rc->suite.edhoc_hash, &rc->th3, &ptxt3, &cred_i,
			   &NULL_ARRAY, &rc->th4));
#endif
	/*TH4*/
	// ptxt3.len = ptxt3.len - get_aead_mac_len(rc->suite.edhoc_aead);
	/*TRY(th34_calculate(rc->suite.edhoc_hash, &rc->th3, &ptxt3, &cred_i,
			   &rc->th4));*/
	
#ifndef KEM_AUTH
	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
#endif
	return ok;
}

#ifndef KEM_AUTH
#ifdef MESSAGE_4
enum err msg4_gen(struct edhoc_responder_context *c, struct runtime_context *rc)
{
	/*Ciphertext 4 calculate*/
	BYTE_ARRAY_NEW(ctxt4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
#if PLAINTEXT4_SIZE != 0
	BYTE_ARRAY_NEW(ptxt4, PLAINTEXT4_SIZE, PLAINTEXT4_SIZE);
#else
	struct byte_array ptxt4 = BYTE_ARRAY_INIT(NULL, 0);
#endif

	TRY(ciphertext_gen(CIPHERTEXT4, &rc->suite, &NULL_ARRAY, &NULL_ARRAY,
			   &NULL_ARRAY, &c->ead_4, &rc->prk_4e3m, &rc->th4,
			   &ctxt4, &ptxt4));

	TRY(encode_bstr(&ctxt4, &rc->msg));

	PRINT_ARRAY("Message 4 ", rc->msg.ptr, rc->msg.len);
	return ok;
}
#endif // MESSAGE_4
#else
enum err msg4_gen(struct edhoc_responder_context *c, struct runtime_context *rc)
{

	BYTE_ARRAY_NEW(sign_or_mac_2, MAC_SIZE,MAC_SIZE);
	TRY(signature_or_mac(GENERATE, rc->static_dh_i, &rc->suite, &c->sk_r,
			     &c->pk_r, &rc->prk_3e2m, &c->c_r, &rc->th4,
			     &c->id_cred_r, &c->cred_r, &c->ead_4, MAC_2,
			     &sign_or_mac_2));
		 
	/*Ciphertext 4 calculate*/
	BYTE_ARRAY_NEW(ctxt4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
	//BYTE_ARRAY_NEW(ptxt4, PLAINTEXT4_SIZE, PLAINTEXT4_SIZE);
	PRINTF("ptxt_buf_capacity %d\n", rc->plaintext_4.len);
    rc->plaintext_4.len = PLAINTEXT4_SIZE;	
	rc->plaintext_4.ptr = (uint8_t *)rc->plaintext_4_buf;	
	TRY(ciphertext_gen(CIPHERTEXT4, &rc->suite, &NULL_ARRAY, &NULL_ARRAY,
			   &sign_or_mac_2, &c->ead_4, &rc->prk_4e3m, &rc->th4,
			   &ctxt4, &rc->plaintext_4));	
    msg_encode(&rc->cc_I, &ctxt4, &rc->msg);
	//TRY(encode_bstr(&ctxt4, &rc->msg));

	PRINT_ARRAY("Message 4 ", rc->msg.ptr, rc->msg.len);
	return ok;
}
enum err msg5_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct cred_array *cred_i_array,
		      struct byte_array *prk_out,
		      struct byte_array *initiator_pk)
{
	PRINT_ARRAY("message5 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);
    BYTE_ARRAY_NEW(ciphertext5, CIPHERTEXT5_SIZE, CIPHERTEXT5_SIZE);
    BYTE_ARRAY_NEW(plaintext5,
		       PLAINTEXT5_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ciphertext5.len);	
	BYTE_ARRAY_NEW(sign_or_mac, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);
	TRY(decode_bstr(&rc->msg, &ciphertext5));
	TRY(ciphertext_decrypt_split(CIPHERTEXT5, &rc->suite, NULL, &NULL_ARRAY,
				     &sign_or_mac, &rc->ead, &rc->prk_4e3m,
				     &rc->th4, &ciphertext5, &plaintext5));
	PRINT_ARRAY("sign_or_mac 1", sign_or_mac.ptr, sign_or_mac.len);
	PRINT_ARRAY("plaintext5", plaintext5.ptr, plaintext5.len);
	PRINT_ARRAY("EAD", rc->ead.ptr, rc->ead.len);	
	bool static_dh_i = false, static_dh_r = false;
	authentication_type_get(rc->method, &static_dh_i, &static_dh_r);
	/*check the authenticity of the responder*/
	//BYTE_ARRAY_NEW(id_cred_r, ID_CRED_R_SIZE);
	/*TE_ARRAY_NEW(cred_r, CRED_R_SIZE, CRED_R_SIZE);
	BYTE_ARRAY_NEW(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_r, G_R_SIZE, G_R_SIZE);*/
	struct byte_array cred_i;
	struct byte_array pk;
	struct byte_array g_i;
	PRINTF("static_dh_i:%d\n", static_dh_i);
	PRINT_ARRAY("cred_i_array->ptr", cred_i_array->ptr, cred_i_array->len);
	PRINT_ARRAY("sign_or_mac 2", sign_or_mac.ptr, sign_or_mac.len);
	PRINT_ARRAY("rc->id_cred_i", rc->id_cred_i.ptr, rc->id_cred_i.len);	
	TRY(retrieve_authenticated_cred(static_dh_i, cred_i_array, &rc->id_cred_i,
                                &cred_i, &pk, &g_i));
	PRINT_ARRAY("sign_or_mac after retrieve", sign_or_mac.ptr, sign_or_mac.len);
		/*calculate STH5*/
	BYTE_ARRAY_NEW(th5, HASH_SIZE, HASH_SIZE);
	PRINT_ARRAY("rc->th4", rc->th4.ptr, rc->th4.len);
	PRINT_ARRAY("rc->plaintext_4", rc->plaintext_4.ptr, rc->plaintext_4.len);
	th5_calculate(rc->suite.edhoc_hash, &rc->th4, &rc->plaintext_4, &th5);
	TRY(signature_or_mac(VERIFY, static_dh_i, &rc->suite, NULL, &pk,
			     &rc->prk_4e3m, &NULL_ARRAY, &th5, &rc->id_cred_i, &cred_i, &rc->ead,
			     MAC_3, &sign_or_mac));

	/*TH4*/
	// ptxt3.len = ptxt3.len - get_aead_mac_len(rc->suite.edhoc_aead);
	/*TRY(th34_calculate(rc->suite.edhoc_hash, &rc->th3, &ptxt3, &cred_i,
			   &rc->th4));*/

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	return ok;
}
#endif
enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	struct byte_array *initiator_pub_key, struct byte_array *c_i_bytes,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	//printf("----------------- PQ EDHOC HANDSHAKE ------------------\n");
	/*receive message 1*/
	//printf("Waiting to receive message 1...\n");
	TRY(rx(c->sock, &rc.msg));
	//printf("MSG 1 size: %d\n",rc.msg.len);

	/*create and send message 2*/
	//printf("-------------------------------------------------------\n");
	//printf("Generating message 2...\n");
	TRY(msg2_gen(c, &rc, c_i_bytes));
	TRY(ead_process(c->params_ead_process, &rc.ead));
	//printf("MSG 2 size: %d\n",rc.msg.len);
	//printf("Sending message 2...\n");
	TRY(tx(c->sock, &rc.msg));

	/*receive message 3*/
	//printf("-------------------------------------------------------\n");
	//printf("waiting to receive message 3...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));
	//printf("MSG 3 size: %d\n",rc.msg.len);
	//printf("-------------------------------------------------------\n");
	TRY(msg3_process(c, &rc, cred_i_array, prk_out, initiator_pub_key));
	TRY(ead_process(c->params_ead_process, &rc.ead));

	/*create and send message 4*/
#ifndef KEM_AUTH
#ifdef MESSAGE_4
	TRY(msg4_gen(c, &rc));
	TRY(tx(c->sock, &rc.msg));
#endif // MESSAGE_4
#else
	TRY(msg4_gen(c, &rc));
	TRY(ead_process(c->params_ead_process, &rc.ead));
	//printf("MSG 2 size: %d\n",rc.msg.len);
	//printf("Sending message 2...\n");
	TRY(tx(c->sock, &rc.msg));
	/*receive message 5*/
	//printf("-------------------------------------------------------\n");
	PRINTF("waiting to receive message 5...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));
	TRY(msg5_process(c, &rc, cred_i_array, prk_out, initiator_pub_key));
#endif

	return ok;
}

enum err edhoc_responder_run(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	BYTE_ARRAY_NEW(c_i, C_I_SIZE, C_I_SIZE);
	return edhoc_responder_run_extended(c, cred_i_array, err_msg, prk_out,
					    &NULL_ARRAY, &c_i, tx, rx,
					    ead_process);
}
