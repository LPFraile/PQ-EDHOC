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
#ifdef LIBOQS
#include <oqs/kem.h>
#endif
#ifdef PQM4
#include <api.h>
#endif
#ifdef MUPQ
#include <api.h>
#endif
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
	#if defined(PQM4) || defined(LIBOQS) 
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
		suite->edhoc_ecdh = HQC_LEVEL1;
		suite->edhoc_sign = FALCON_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_11:
		suite->suite_label = SUITE_11;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = BIKE_LEVEL1;
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
		case SUITE_13:
		suite->suite_label = SUITE_13;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = BIKE_LEVEL1;
		suite->edhoc_sign = DILITHIUM_LEVEL2;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_14:
		suite->suite_label = SUITE_14;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = HAWK_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_15:
		suite->suite_label = SUITE_15;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = HAETAE_LEVEL2;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
		case SUITE_16:
		suite->suite_label = SUITE_16;
		suite->edhoc_aead = AES_CCM_16_64_128;
		suite->edhoc_hash = SHA_256;
		suite->edhoc_mac_len_static_dh = MAC8;
		suite->edhoc_ecdh = KYBER_LEVEL1;
		suite->edhoc_sign = OV_IP_LEVEL1;
		suite->app_aead = AES_CCM_16_64_128;
		suite->app_hash = SHA_256;
	break;
	#endif
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
	#ifdef LIBOQS
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
		return OQS_SIG_ml_dsa_44_ipd_length_signature;
		//return OQS_SIG_dilithium_2_length_signature;	
		break;
	#endif
	#ifdef PQM4
	case FALCON_LEVEL1:
		return 690; //Was working before with 690
		break;
	case DILITHIUM_LEVEL2:
		return 2420;	
		break;
	case HAWK_LEVEL1:
		return 555;	
		break;
	case HAETAE_LEVEL2:
		return 1474;	
		break;
	#endif
	
	#if(defined MUPQ) && (!defined(PQM4))
	case HAWK_LEVEL1:
		return 555;	
		break;
	case HAETAE_LEVEL2:
		return 1474;	
		break;
	#endif

	default: 
		return 0;
	}
	return 0;
}

uint32_t get_sk_len(enum sign_alg alg)
{
	switch (alg) {
	case ES256:
	case EdDSA:
		return 32;
		break;
	#ifdef LIBOQS
	case FALCON_LEVEL1:
		return OQS_SIG_falcon_512_length_secret_key;
		break;
	case FALCON_LEVEL5:
		return OQS_SIG_falcon_1024_length_secret_key;
		break;
	case FALCON_PADDED_LEVEL1:
		return OQS_SIG_falcon_padded_512_length_secret_key;
		break;
	case FALCON_PADDED_LEVEL5:
		return OQS_SIG_falcon_padded_1024_length_secret_key;	
		break;
	case DILITHIUM_LEVEL2:
		//return OQS_SIG_dilithium_2_length_secret_key;	
		return OQS_SIG_ml_dsa_44_ipd_length_secret_key;	
		break;
	#endif
	#ifdef PQM4
	case FALCON_LEVEL1:
		return 1281; //Was working before with 690
		break;
	case DILITHIUM_LEVEL2:
		return 2560;	
		break;
	case HAWK_LEVEL1:
		return 184;	
		break;
	case HAETAE_LEVEL2:
		return 1408;	
		break;
	#endif
	
	#if(defined MUPQ) && (!defined(PQM4))
	case HAWK_LEVEL1:
		return 184;	
		break;
	case HAETAE_LEVEL2:
		return 1404;	
		break;
	#endif

	default: 
		return 0;
	}
	return 0;
}

uint32_t get_pk_len(enum sign_alg alg)
{
	switch (alg) {
	case ES256:
	case EdDSA:
		return 32;
		break;
	#ifdef LIBOQS
	case FALCON_LEVEL1:
		return OQS_SIG_falcon_512_length_public_key;
		break;
	case FALCON_LEVEL5:
		return OQS_SIG_falcon_1024_length_public_key;
		break;
	case FALCON_PADDED_LEVEL1:
		return OQS_SIG_falcon_padded_512_length_public_key;
		break;
	case FALCON_PADDED_LEVEL5:
		return OQS_SIG_falcon_padded_1024_length_public_key;	
		break;
	case DILITHIUM_LEVEL2:
		//return OQS_SIG_dilithium_2_length_public_key;	
		return OQS_SIG_ml_dsa_44_ipd_length_public_key;	
		break;
	#endif
	#ifdef PQM4
	case FALCON_LEVEL1:
		return 897; //Was working before with 690
		break;
	case DILITHIUM_LEVEL2:
		return 1312;	
		break;
	case HAWK_LEVEL1:
		return 1024;	
		break;
	case HAETAE_LEVEL2:
		return 992;	
		break;
	#endif
	
	#if(defined MUPQ) && (!defined(PQM4))
	case HAWK_LEVEL1:
		return 1024;	
		break;
	case HAETAE_LEVEL2:
		return 992;	
		break;
	#endif

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
	#ifdef LIBOQS
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
	case BIKE_LEVEL1:
		return OQS_KEM_bike_l1_length_public_key;
		break;
	#endif
	#ifdef PQM4
	case KYBER_LEVEL1:
		return 800;
		break;
	case KYBER_LEVEL3:
		return 1184;
		break;
	case HQC_LEVEL1:
		return 2249;
		break;
	case BIKE_LEVEL1:
		return 1541;
		break;
	#endif
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_kem_pk_len(enum ecdh_alg alg)
{
	switch (alg) {
	#ifdef LIBOQS
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
	case BIKE_LEVEL1:
		return OQS_KEM_bike_l1_length_public_key;
		break;
	#endif
	#ifdef PQM4
	case KYBER_LEVEL1:
		return 800;
		break;
	case KYBER_LEVEL3:
		return 1184;
		break;
	case HQC_LEVEL1:
		return 2249;
		break;
	case BIKE_LEVEL1:
		return 1541;
		break;
	#endif
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_kem_sk_len(enum ecdh_alg alg)
{
	switch (alg) {
	#ifdef LIBOQS
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
	case BIKE_LEVEL1:
		return OQS_KEM_bike_l1_length_secret_key;
		break;
	#endif
	#ifdef PQM4
	case KYBER_LEVEL1:
		return 1632;
		break;
	case KYBER_LEVEL3:
		return 2400;
		break;
	case HQC_LEVEL1:
		return 2305;
		break;
	case BIKE_LEVEL1:
		return 5223;
		break;
	#endif
	default: 
		return 0;
	}
	return 0;
}

uint32_t get_kem_cc_len(enum ecdh_alg alg)
{
	switch (alg) {
	#ifdef LIBOQS
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
	case BIKE_LEVEL1:
		return OQS_KEM_bike_l1_length_ciphertext;
		break;
	#endif
	#ifdef PQM4
	case KYBER_LEVEL1:
		return 768;
		break;
	case KYBER_LEVEL3:
		return 1088;
		break;
	case HQC_LEVEL1:
		return 4433;
		break;
	case BIKE_LEVEL1:
		return 1573;
		break;
	#endif
	default: 
		return 0;
	}

	return 0;
}

uint32_t get_kem_ss_len(enum ecdh_alg alg)
{
	switch (alg) {
	#ifdef LIBOQS
	case KYBER_LEVEL1:
		return 32;
		break;
	case KYBER_LEVEL3:
		return 32;
		break;
	case KYBER_LEVEL5:
		return 32;
		break;
	case HQC_LEVEL1:
		return 64;
		break;
	case BIKE_LEVEL1:
		return 32;
		break;
	#endif
	#ifdef PQM4
	case KYBER_LEVEL1:
		return 32;
		break;
	case KYBER_LEVEL3:
		return 32;
		break;
	case HQC_LEVEL1:
		return 64;
		break;
	case BIKE_LEVEL1:
		return 32;
		break;
	#endif
	default: 
		return 0;
	}

	return 0;
}