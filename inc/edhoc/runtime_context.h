/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef RUNTIME_CONTEXT_H
#define RUNTIME_CONTEXT_H

#include <stdint.h>

#include "common/byte_array.h"
#include "edhoc/buffer_sizes.h"
#include "edhoc/suites.h"

struct runtime_context {
	uint8_t msg_buf[MSG_MAX_SIZE];
	struct byte_array msg;
#if EAD_SIZE != 0
	uint8_t ead_buf[EAD_SIZE];
#endif
	struct byte_array ead;
	struct suite suite;
	uint8_t msg1_hash_buf[HASH_SIZE];
	struct byte_array msg1_hash;

	/*initiator specific*/
	uint8_t th4_buf[HASH_SIZE];
	struct byte_array th4;
	uint8_t prk_4e3m_buf[PRK_SIZE];
	struct byte_array prk_4e3m;
	uint8_t id_cred_r_buf[ID_CRED_R_SIZE];
	struct byte_array id_cred_r;
	

	/*responder specific*/
	bool static_dh_i;
	uint8_t th3_buf[HASH_SIZE];
	struct byte_array th3;
	uint8_t prk_3e2m_buf[PRK_SIZE];
	struct byte_array prk_3e2m;
	/*Add it by PQ*/
	int32_t method;
	uint8_t id_cred_i_buf[ID_CRED_I_SIZE];
	struct byte_array id_cred_i;
	

	/*responder specific*/
	uint8_t plaintext_2_buf[PLAINTEXT2_SIZE];
	struct byte_array plaintext_2;
	uint8_t plaintext_3_buf[PLAINTEXT3_SIZE];
	struct byte_array plaintext_3;
	uint8_t plaintext_4_buf[PLAINTEXT4_SIZE];
	struct byte_array plaintext_4;
	uint8_t th2_buf[HASH_SIZE];
	struct byte_array th2;
	uint8_t prk_2e_buf[PRK_SIZE];
	struct byte_array prk_2e;
	//#ifdef KEM_AUTH
	uint8_t cc_R_buf[G_Y_SIZE];
	struct byte_array cc_R;
	uint8_t cc_I_buf[G_Y_SIZE];
	struct byte_array cc_I;
	uint8_t ss_R_buf[ECDH_SECRET_SIZE];
	struct byte_array ss_R;
	uint8_t ss_I_buf[ECDH_SECRET_SIZE];
	struct byte_array ss_I;
	//#endif
};

#endif
