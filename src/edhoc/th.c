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

#include "edhoc/th.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_encode_data_2.h"
#include "cbor/edhoc_encode_th2.h"

#include "edhoc/edhoc_method_type.h"
/**
 * @brief   			Setups a data structure used as input for th2, 
 * 				namely CBOR sequence H( G_Y, C_R, H(message_1)).
 *
 * @param[in] hash_msg1 	Hash of message 1.
 * @param[in] g_y 		Ephemeral public DH key.
 * @param[out] th2_input	The result.
 * @retval			Ok or error.
 */
static inline enum err th2_input_encode(struct byte_array *hash_msg1,
					struct byte_array *g_y,
					struct byte_array *th2_input)
{
	size_t payload_len_out;
	struct th2 th2;

	/*Encode hash_msg1*/
	th2.th2_hash_msg1.value = hash_msg1->ptr;
	th2.th2_hash_msg1.len = hash_msg1->len;

	/*Encode G_Y*/
	th2.th2_G_Y.value = g_y->ptr;
	th2.th2_G_Y.len = g_y->len;

	TRY_EXPECT(cbor_encode_th2(th2_input->ptr, th2_input->len, &th2,
				   &payload_len_out),
		   0);

	/* Get the the total th2 length */
	th2_input->len = (uint32_t)payload_len_out;

	PRINT_ARRAY("Input to calculate TH_2 (CBOR Sequence)", th2_input->ptr,
		    th2_input->len);
	return ok;
}

/**
 * @brief   			Setups a data structure used as input for 
 * 				th3 or th4.
 * @param[in] m                     Method type.
 * @param[in] th23 		th2 or th3.
 * @param[in] plaintext_23 	Plaintext 2 or plaintext 3.
 * @param[in] cred		The credential.
 * @param[in] ct                Ct_I  or ct_R . 
 * @param[out] th34_input 	The result.
 * @retval			Ok or error code.
 */
static enum err th34_input_encode(enum method_type m,struct byte_array *th23,
				  struct byte_array *plaintext_23,
				  const struct byte_array *cred,
				  struct byte_array *ct,
				  struct byte_array *th34_input)
{
	PRINT_MSG("th34_input_encode\n");
	PRINT_ARRAY("th23", th23->ptr, th23->len);
	PRINT_ARRAY("plaintext_23", plaintext_23->ptr, plaintext_23->len);
	PRINT_ARRAY("cred", cred->ptr, cred->len);
	PRINT_ARRAY("ct", ct->ptr, ct->len);
	PRINTF("th34_input->len: %d\n", th34_input->len);

	size_t th34_input_cap = th34_input->len;
	TRY(encode_bstr(th23, th34_input));
	uint32_t tmp_len = th34_input->len;
	// PRINTF("tmp_len: %d, th34_input->len: %d, cred->len: %d\n", tmp_len, th34_input->len, cred->len);
	/*TRY(_memcpy_s(th34_input->ptr + tmp_len,
		      th34_input->len - tmp_len - cred->len, plaintext_23->ptr,
		      plaintext_23->len));*/
	TRY(_memcpy_s(th34_input->ptr + tmp_len,
		      th34_input_cap - tmp_len, plaintext_23->ptr,
		      plaintext_23->len));
	tmp_len += plaintext_23->len;
    PRINTF("tmp_len: %d, th34_input->len: %d, cred->len: %d\n", tmp_len, th34_input->len, cred->len);
	TRY(_memcpy_s(th34_input->ptr + tmp_len, th34_input_cap - tmp_len,
		      cred->ptr, cred->len));
	
	tmp_len += cred->len;
	if(m >= 4){
		PRINT_MSG("Add ct to th34_input\n");
		PRINTF("ct len: %d\n", ct->len);
		TRY(_memcpy_s(th34_input->ptr + tmp_len, th34_input_cap - tmp_len,
		      ct->ptr, ct->len));
		/*TRY(_memcpy_s(th34_input->ptr + tmp_len, th34_input->len - tmp_len,
		      ct->ptr, ct->len));*/
		th34_input->len = tmp_len + ct->len;
	}
	else{

		th34_input->len = tmp_len;
   }

	PRINT_ARRAY("Input to calculate TH_3/TH_4 (CBOR Sequence)",
		    th34_input->ptr, th34_input->len);
	return ok;
}


/**
 * @brief   			Setups a data structure used as input for th5
 * 		
 * @param[in] th4 		th4 
 * @param[in] plaintext_4 	Plaintext 4.
 * @param[out] th5_input 	The result.
 * @retval			Ok or error code.
 */
static enum err th5_input_encode(struct byte_array *th4,
				  struct byte_array *plaintext_4,
				  struct byte_array *th5_input)
{
	PRINT_MSG("th5_input_encode\n");
 PRINT_ARRAY("th4", th4->ptr, th4->len);
 PRINT_ARRAY("plaintext_4", plaintext_4->ptr, plaintext_4->len);
 PRINT_ARRAY("th5_input", th5_input->ptr, th5_input->len);
 size_t th5_input_cap = th5_input->len;
	TRY(encode_bstr(th4, th5_input));
 PRINT_ARRAY("th5_input", th5_input->ptr, th5_input->len);
	uint32_t tmp_len = th5_input->len;
   PRINT_MSG("Copy plaintext_4 to th5_input\n");
   PRINTF("tmp_len: %d, th5_input->len: %d, plaintext_4->len: %d\n", tmp_len, th5_input->len, plaintext_4->len);
	TRY(_memcpy_s(th5_input->ptr + tmp_len,
		      th5_input_cap - tmp_len, plaintext_4->ptr,
		      plaintext_4->len));

	tmp_len += plaintext_4->len;
	
	th5_input->len = tmp_len;

	PRINT_ARRAY("Input to calculate TH_5 (CBOR Sequence)",
		    th5_input->ptr, th5_input->len);
	return ok;
}

/**
 * @brief                       Calculates transcript hash th3/th4 
 *                              TH_3 = H(TH_2, PLAINTEXT_2) 
 *                              TH_4 = H(TH_3, PLAINTEXT_3) 
 * @param m                     Method type.
 * @param alg                   Hash algorithm to be used.
 * @param[in] th23              th2 ot th3.
 * @param[in] plaintext_23      Plaintext 2 or plaintext 3.
 * @param[in] cred              The credential.
 * @param[in] ct                Ct_I  or ct_R .  
 * @param[out] th34             The result.
 * @retval                      Ok or error.
 */
enum err th34_calculate(enum method_type m, enum hash_alg alg, struct byte_array *th23,
			struct byte_array *plaintext_23,
			const struct byte_array *cred,struct byte_array *ct, struct byte_array *th34)
{
	if(m < 4){
		PRINT_MSG("th34_calculate: m < 4\n");
	uint32_t th34_input_len =
		AS_BSTR_SIZE(get_hash_len(alg)) + plaintext_23->len + cred->len;
	BYTE_ARRAY_NEW(th34_input, TH34_INPUT_SIZE, th34_input_len);

	TRY(th34_input_encode(m, th23, plaintext_23, cred, ct, &th34_input));
	TRY(hash(alg, &th34_input, th34));
	}else{
		PRINT_MSG("th34_calculate: m >= 4\n");
		uint32_t th34_input_len =
		AS_BSTR_SIZE(get_hash_len(alg)) + plaintext_23->len + cred->len + ct->len;
		BYTE_ARRAY_NEW(th34_input, TH34_INPUT_SIZE, th34_input_len);

		TRY(th34_input_encode(m, th23, plaintext_23, cred, ct, &th34_input));
		TRY(hash(alg, &th34_input, th34));
	}
	
	PRINT_ARRAY("TH34", th34->ptr, th34->len);
	return ok;
}

enum err th2_calculate(enum hash_alg alg, struct byte_array *msg1_hash,
		       struct byte_array *g_y, struct byte_array *th2)
{
	BYTE_ARRAY_NEW(th2_input, TH2_INPUT_SIZE,
		       AS_BSTR_SIZE(g_y->len) +
			       AS_BSTR_SIZE(get_hash_len(alg)));
	PRINT_ARRAY("hash_msg1_raw", msg1_hash->ptr, msg1_hash->len);
	TRY(th2_input_encode(msg1_hash, g_y, &th2_input));
	TRY(hash(alg, &th2_input, th2));
	PRINT_ARRAY("TH2", th2->ptr, th2->len);
	return ok;
}

enum err th5_calculate(enum hash_alg alg,  struct byte_array *th4, struct byte_array *plaintext_4,  struct byte_array *th5)
{
	PRINTF("th5_calculate\n");
	PRINTF("th4 len: %d\n", th4->len);
	PRINTF("plaintext_4 len: %d\n", plaintext_4->len);
	PRINTF("hash len: %d\n", get_hash_len(alg));
	PRINTF("TH5_INPUT_SIZE: %d\n", TH5_INPUT_SIZE);
	PRINT_ARRAY("th4", th4->ptr, th4->len);
	PRINT_ARRAY("plaintext_4", plaintext_4->ptr, plaintext_4->len);
	uint32_t th5_input_len =
		AS_BSTR_SIZE(get_hash_len(alg)) + plaintext_4->len;
	BYTE_ARRAY_NEW(th5_input, TH5_INPUT_SIZE, th5_input_len);

	TRY(th5_input_encode(th4,plaintext_4, &th5_input));
	TRY(hash(alg, &th5_input, th5));
	PRINT_ARRAY("TH5", th5->ptr, th5->len);
	return ok;
}