/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/suites.h"

#include "common/oscore_edhoc_error.h"
#include <oqs/kem.h>

enum err get_suite(enum suite_label label, struct suite *suite)
{
	switch (label) {
	case SUITE_0:
		suite->suite_label = SUITE_0;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_1:
		suite->suite_label = SUITE_1;
		suite->edhoc_aead = AES_CCM_16_128_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = X25519;
		suite->edhoc_sign = EdDSA;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_2:
		suite->suite_label = SUITE_2;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = P256;
		suite->edhoc_sign = ES256;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE_3:
		suite->suite_label = SUITE_3;
		suite->edhoc_aead = AES_CCM_16_128_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = P256;
		suite->edhoc_sign = ES256;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
		break;
	case SUITE__22:
		suite->suite_label = SUITE__22;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = ES256;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_7:
		suite->suite_label = SUITE_7;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = FALCON_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_8:
		suite->suite_label = SUITE_8;
		suite->edhoc_aead = AES_CCM_16_128_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC16;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = FALCON_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
	case SUITE_9:
		suite->suite_label = SUITE_9;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL3;
		suite->edhoc_sign = FALCON_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_10:
		suite->suite_label = SUITE_10;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1	;
		suite->edhoc_sign = FALCON_PADDED_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_11:
		suite->suite_label = SUITE_11;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = HQC_LEVEL1;
		suite->edhoc_sign = FALCON_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_12:
		suite->suite_label = SUITE_12;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = DILITHIUM_LEVEL2;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
	default:
		return unsupported_cipher_suite;
		break;
	}
	return ok;
}

uint32_t get_hash_len(enum hash_alg alg)
{
	switch (alg) {
	case SHA_256:
		return 32;
		break;
	}
	return 0;
}

uint32_t get_aead_mac_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
		return 16;
		break;
	case AES_CCM_16_64_128:
		return 8;
		break;
	}
	return 0;
}

uint32_t get_aead_key_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case AES_CCM_16_64_128:
		return 16;
		break;
	}
	return 0;
}

uint32_t get_aead_iv_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case AES_CCM_16_64_128:
		return 13;
		break;
	}
	return 0;
}

uint32_t get_signature_len(enum sign_alg alg)
{
	switch (alg) {
	case ES256:
	case EdDSA:
		return 64;
		break;
	case FALCON_LEVEL1:
		return OQS_SIG_falcon_512_length_signature;
		break;
	case FALCON_LEVEL5:
		return OQS_SIG_falcon_1024_length_signature;
		break;
	case FALCON_PADDED_LEVEL1:
		return OQS_SIG_falcon_padded_512_length_signature;
		break;
	case FALCON_PADDED_LEVEL5:
		return OQS_SIG_falcon_padded_1024_length_signature;	
		break;
	case DILITHIUM_LEVEL2:
		return OQS_SIG_dilithium_2_length_signature;	
		break;
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_ecdh_pk_len(enum ecdh_alg alg)
{
	switch (alg) {
	case P256:
		/*the x coordinate of the public key*/
		return 32;
		break;
	case X25519:
		return 32;
		break;
	case KYBER_LEVEL1:
		return OQS_KEM_ml_kem_512_length_public_key;
		break;
	case KYBER_LEVEL3:
		return OQS_KEM_ml_kem_768_length_public_key;
		break;
	case KYBER_LEVEL5:
		return OQS_KEM_ml_kem_1024_length_public_key;
		break;
	case HQC_LEVEL1:
		return OQS_KEM_hqc_128_length_public_key;
		break;
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_kem_pk_len(enum ecdh_alg alg)
{
	switch (alg) {
	case KYBER_LEVEL1:
		return OQS_KEM_ml_kem_512_length_public_key;
		break;
	case KYBER_LEVEL3:
		return OQS_KEM_ml_kem_768_length_public_key;
		break;
	case KYBER_LEVEL5:
		return OQS_KEM_ml_kem_1024_length_public_key;
		break;
	case HQC_LEVEL1:
		return OQS_KEM_hqc_128_length_public_key;
		break;
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_kem_sk_len(enum ecdh_alg alg)
{
	switch (alg) {
	case KYBER_LEVEL1:
		return OQS_KEM_ml_kem_512_length_secret_key;
		break;
	case KYBER_LEVEL3:
		return OQS_KEM_ml_kem_768_length_secret_key;
		break;
	case KYBER_LEVEL5:
		return OQS_KEM_ml_kem_1024_length_secret_key;
		break;
	case HQC_LEVEL1:
		return OQS_KEM_hqc_128_length_secret_key;
		break;
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_kem_cc_len(enum ecdh_alg alg)
{
	switch (alg) {
	case KYBER_LEVEL1:
		return OQS_KEM_ml_kem_512_length_ciphertext;
		break;
	case KYBER_LEVEL3:
		return OQS_KEM_ml_kem_768_length_ciphertext;
		break;
	case KYBER_LEVEL5:
		return OQS_KEM_ml_kem_1024_length_ciphertext;
		break;
	case HQC_LEVEL1:
		return OQS_KEM_hqc_128_length_ciphertext;
		break;
	default: 
		return 0;
	}

	return 0;
}