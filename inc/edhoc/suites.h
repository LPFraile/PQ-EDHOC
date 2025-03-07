/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef SUITES_H
#define SUITES_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/*see https://www.iana.org/assignments/cose/cose.xhtml#algorithms for algorithm number reference*/

enum suite_label {
	SUITE_0 = 0,
	SUITE_1 = 1,
	SUITE_2 = 2,
	SUITE_3 = 3,
	SUITE__22 = 22,
	SUITE_7 = 7,
	SUITE_8 = 8,
	SUITE_9 = 9,
	SUITE_10 = 10,
	SUITE_11 = 11,
	SUITE_12 = 12,
	SUITE_13 = 13,
	SUITE_14 = 14,
	SUITE_15 = 15,
	SUITE_16 = 16,
};

enum aead_alg {
	AES_CCM_16_64_128 = 10,
	AES_CCM_16_128_128 = 30,
};

enum hash_alg { SHA_256 = -16 };

enum ecdh_alg {
	P256 = 1,
	X25519 = 4,
	KYBER_LEVEL1 = -48, 
	KYBER_LEVEL3 = -49,
	KYBER_LEVEL5 = -50,
	HQC_LEVEL1 = -51,
	BIKE_LEVEL1 = -52,
};

enum sign_alg {
	ES256 = -7,
	EdDSA = -8,
	FALCON_LEVEL1 = -57,
	FALCON_LEVEL5 = -58,
	FALCON_PADDED_LEVEL1 = -59,
	FALCON_PADDED_LEVEL5 = -60,
	DILITHIUM_LEVEL2 = -61,
	DILITHIUM_LEVEL3 = -62,
	DILITHIUM_LEVEL5 = -63,
	HAWK_LEVEL1 = -64,
	HAETAE_LEVEL2 = -65,
	OV_IP_LEVEL1 = -66,

	/*ML_DSA_LEVEL2 = -,
	ML_DSA_LEVEL3 = -,
	ML_DSA_LEVEL5 = -*/
};

enum mac_len {
	MAC8 = 8,
	MAC16 = 16,
};

struct suite {
	enum suite_label suite_label;
	enum aead_alg edhoc_aead;
	enum hash_alg edhoc_hash;
	enum mac_len edhoc_mac_len_static_dh;
	enum ecdh_alg edhoc_ecdh;
	enum sign_alg edhoc_sign;
	enum aead_alg app_aead;
	enum hash_alg app_hash;
};

/**
 * @brief   			Retrieves the algorithms corrsponding to a 
 * 				given suite label.
 * 
 * @param label 		The label of the suite.
 * @param suite 		The algorithms corrsponding to label.
 * @retval			Ok or error.
 */
enum err get_suite(enum suite_label label, struct suite *suite);

/**
 * @brief 			Gets the length of the hash.
 * 
 * @param alg 			The used hash algorithm.
 * @retval			The length.
 */
uint32_t get_hash_len(enum hash_alg alg);

/**
 * @brief 			Gets the length of the MAC.
 * 
 * @param alg 			The used AEAD algorithm.
 * @retval 			The length.
 */
uint32_t get_aead_mac_len(enum aead_alg alg);

/**
 * @brief 			Gets the length of KEY.
 * 
 * @param alg 			The used AEAD algorithm.
 * @retval 			The length.
 */
uint32_t get_aead_key_len(enum aead_alg alg);

/**
 * @brief 			Gets the length of IV.
 * 
 * @param alg 			The used AEAD algorithm.
 * @retval 			The length.
 */
uint32_t get_aead_iv_len(enum aead_alg alg);

/**
 * @brief 			Gets the length of the signature.
 * 
 * @param alg 			The used signature algorithm.
 * @retval			The length.
 */
uint32_t get_signature_len(enum sign_alg alg);


/**
 * @brief 			Gets the length of the secret key for auth.
 * 
 * @param alg 			The used signature algorithm.
 * @retval			The length.
 */
uint32_t get_sk_len(enum sign_alg alg);

/**
 * @brief 			Gets the length of the public key for auth.
 * 
 * @param alg 			The used signature algorithm.
 * @retval			The length.
 */
uint32_t get_pk_len(enum sign_alg alg);


/**
 * @brief 			Gets the length of the ECDH public key.
 * 
 * @param alg 			The used ECDH algorithm. 
 * @retval 			The length.
 */
uint32_t get_ecdh_pk_len(enum ecdh_alg alg);


/**
 * @brief 			Gets the length of the CC size on KEMs.
 * 
 * @param alg 			The used KEM algorithm. 
 * @retval 			The length.
 */
uint32_t get_kem_cc_len(enum ecdh_alg alg);


/**
 * @brief 			Gets the length of the publick key size on KEMs.
 * 
 * @param alg 			The used KEM algorithm. 
 * @retval 			The length.
 */
uint32_t get_kem_pk_len(enum ecdh_alg alg);

/**
 * @brief 			Gets the length of the secret key size size on KEMs.
 * 
 * @param alg 			The used KEM algorithm. 
 * @retval 			The length.
 */
uint32_t get_kem_sk_len(enum ecdh_alg alg);



/**
 * @brief 			Gets the length of the shared secret on KEMs.
 * 
 * @param alg 			The used KEM algorithm. 
 * @retval 			The length.
 */
uint32_t get_kem_ss_len(enum ecdh_alg alg);
#endif
