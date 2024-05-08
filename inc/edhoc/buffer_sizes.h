/*
 * Copyright (c) 2023 Eriptic Technologies
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef BUFFER_SIZES_H
#define BUFFER_SIZES_H
#include <oqs/kem.h>

#ifdef HQC_LEVEL_1
	#define PQ_KEM HQC_LEVEL1
	#define G_Y_SIZE OQS_KEM_hqc_128_length_ciphertext
	#define G_X_SIZE OQS_KEM_hqc_128_length_public_key
	#define G_I_SIZE OQS_KEM_hqc_128_length_secret_key
	#define ECDH_SECRET_SIZE 64
#endif

#ifdef KYBER_LEVEL_3 
#ifndef HQC_LEVEL_1
	#define PQ_KEM KYBER_LEVEL3
	#define G_Y_SIZE OQS_KEM_kyber_768_length_ciphertext
	#define G_X_SIZE OQS_KEM_kyber_768_length_public_key
	#define G_I_SIZE OQS_KEM_kyber_768_length_secret_key
#endif
#endif

#ifdef KYBER_LEVEL_1
#ifndef HQC_LEVEL_1
#ifndef KYBER_LEVEL_3
	#define PQ_KEM KYBER_LEVEL1
	#define G_Y_SIZE OQS_KEM_kyber_512_length_ciphertext
	#define G_X_SIZE OQS_KEM_kyber_512_length_public_key
	#define G_I_SIZE OQS_KEM_kyber_512_length_secret_key

#endif
#endif
#endif

#ifdef FALCON_LEVEL_5
	#define SIGNATURE_SIZE OQS_SIG_falcon_1024_length_signature  
	#define PK_SIZE OQS_SIG_falcon_1024_length_public_key
#endif

#ifdef DILITHIUM_LEVEL_2
	#define SIGNATURE_SIZE OQS_SIG_dilithium_2_length_signature  
	#define PK_SIZE OQS_SIG_dilithium_2_length_public_key
#endif

#ifndef FALCON_LEVEL_5
#ifdef FALCON_LEVEL_1
	#define SIGNATURE_SIZE OQS_SIG_falcon_512_length_signature  
	//#define CRED_I_SIZE 2000
	//#define CRED_R_SIZE 2000
	#define PK_SIZE OQS_SIG_falcon_512_length_public_key
#endif
#endif

#define CRED_I_SIZE PK_SIZE*3
#define CRED_R_SIZE PK_SIZE*3

#ifndef EAD_SIZE
#define EAD_SIZE 0
#endif

#ifndef C_I_SIZE
#define C_I_SIZE 10
#endif

#ifndef C_R_SIZE
#define C_R_SIZE 10
#endif

#ifndef ID_CRED_I_SIZE
#define ID_CRED_I_SIZE 400
#endif

#ifndef ID_CRED_R_SIZE
#define ID_CRED_R_SIZE 400
#endif

#ifndef CRED_I_SIZE
#define CRED_I_SIZE 400
#endif

#ifndef CRED_R_SIZE
#define CRED_R_SIZE 400
#endif

#ifndef SUITES_I_SIZE
#define SUITES_I_SIZE 6
#endif



#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define BSTR_ENCODING_OVERHEAD(x)                                              \
	((x) <= 5) ? 1 : ((x) <= UINT8_MAX) ? 2 : ((x) <= UINT16_MAX) ? 3 : 5

#define P_256_PRIV_KEY_SIZE 32
#define P_256_PUB_KEY_COMPRESSED_SIZE 33
#define P_256_PUB_KEY_UNCOMPRESSED_SIZE 65
#define P_256_PUB_KEY_X_CORD_SIZE 32

#ifndef PK_SIZE
#define PK_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#endif

#ifndef G_Y_SIZE
#define G_Y_SIZE P_256_PUB_KEY_X_CORD_SIZE
#endif

#ifndef G_X_SIZE
#define G_X_SIZE P_256_PUB_KEY_X_CORD_SIZE
#endif

#ifndef G_R_SIZE
#define G_R_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#endif

#ifndef G_I_SIZE
#define G_I_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#endif


#ifndef SIGNATURE_SIZE
#define SIGNATURE_SIZE 64
#endif

#ifndef ECDH_SECRET_SIZE
#define ECDH_SECRET_SIZE 32 /*PQ shared secret has the same size than ecdh secret */
#endif

#define PRK_SIZE 32
#define HASH_SIZE 32
#define AEAD_IV_SIZE 13
#define MAC_SIZE 16
#define MAC23_SIZE 32
#define AAD_SIZE 45
#define KID_SIZE 8
#define SIG_OR_MAC_SIZE SIGNATURE_SIZE
#define ENCODING_OVERHEAD 10
#define COSE_SIGN1_STR_LEN 10 /*the length of the string "COSE_Sign1"*/
#define SIG_OR_MAC_SIZE_ENCODING_OVERHEAD 3 /*we need 3 bbytes to encode PQ signatures*/
#define PLAINTEXT3_SIZE_ENCODING_OVERHEAD 4
//#define SIG_OR_MAC_SIZE_ENCODING_OVERHEAD 2
//#define PLAINTEXT3_SIZE_ENCODING_OVERHEAD 3

#define PLAINTEXT2_SIZE                                                        \
	(ID_CRED_R_SIZE + SIG_OR_MAC_SIZE +                                    \
	 SIG_OR_MAC_SIZE_ENCODING_OVERHEAD + EAD_SIZE)
#define CIPHERTEXT2_SIZE PLAINTEXT2_SIZE

#define PLAINTEXT3_SIZE                                                        \
	(ID_CRED_I_SIZE + SIG_OR_MAC_SIZE +                                    \
	 SIG_OR_MAC_SIZE_ENCODING_OVERHEAD + EAD_SIZE)
#define CIPHERTEXT3_SIZE                                                       \
	(PLAINTEXT3_SIZE + MAC_SIZE + PLAINTEXT3_SIZE_ENCODING_OVERHEAD)

#define PLAINTEXT4_SIZE EAD_SIZE
#define CIPHERTEXT4_SIZE (PLAINTEXT4_SIZE + ENCODING_OVERHEAD)

#define MSG_1_SIZE (1 + SUITES_I_SIZE + G_X_SIZE + C_I_SIZE + EAD_SIZE)
#define MSG_2_SIZE (G_Y_SIZE + CIPHERTEXT2_SIZE + C_R_SIZE + ENCODING_OVERHEAD)
#define MSG_3_SIZE CIPHERTEXT3_SIZE
#define MSG_4_SIZE CIPHERTEXT4_SIZE

#define MSG12_MAX MAX(MSG_1_SIZE, MSG_2_SIZE)
#define MSG34_MAX MAX(MSG_3_SIZE, MSG_4_SIZE)
#define MSG_MAX_SIZE MAX(MSG12_MAX, MSG34_MAX)
#define PLAINTEXT23_MAX_SIZE MAX(PLAINTEXT2_SIZE, PLAINTEXT3_SIZE)
#define CRED_MAX_SIZE MAX(CRED_R_SIZE, CRED_I_SIZE)
#define ID_CRED_MAX_SIZE MAX(ID_CRED_R_SIZE, ID_CRED_I_SIZE)

#define SIG_STRUCT_SIZE                                                        \
	((2 + HASH_SIZE) + COSE_SIGN1_STR_LEN + ID_CRED_MAX_SIZE +             \
	 CRED_MAX_SIZE + EAD_SIZE + MAC23_SIZE + ENCODING_OVERHEAD)

#define CONTEXT_MAC_SIZE                                                       \
	(HASH_SIZE + ID_CRED_MAX_SIZE + CRED_MAX_SIZE + EAD_SIZE +             \
	 ENCODING_OVERHEAD)
#define INFO_MAX_SIZE CONTEXT_MAC_SIZE + ENCODING_OVERHEAD

#define TH34_INPUT_SIZE (HASH_SIZE + PLAINTEXT23_MAX_SIZE + CRED_MAX_SIZE + 2)
#define TH2_DEFAULT_SIZE (G_Y_SIZE + C_R_SIZE + HASH_SIZE + ENCODING_OVERHEAD)

#endif
