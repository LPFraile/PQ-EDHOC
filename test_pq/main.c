/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include "edhoc_integration_tests/edhoc_tests.h"

//#include "oscore_tests.h"

#define TEST_EDHOC_EXPORTER 1
#define TEST_INITIATOR_RESPONDER_INTERACTION1 2
#define TEST_INITIATOR_RESPONDER_INTERACTION2 3
#define T1_OSCORE_CLIENT_REQUEST_RESPONSE 4
#define T2_OSCORE_SERVER_REQUEST_RESPONSE 5
#define T3_OSCORE_CLIENT_REQUEST 6
#define T4_OSCORE_SERVER_KEY_DERIVATION 7
#define T5_OSCORE_CLIENT_REQUEST 8
#define T6_OSCORE_SERVER_KEY_DERIVATION 9
#define T8_OSCORE_SERVER_RESPONSE_SIMPLE_ACK 10
#define T9_OSCORE_CLIENT_SERVER_OBSERVE 11
#define T10_OSCORE_CLIENT_SERVER_AFTER_REBOOT 12
#define T100_INNER_OUTER_OPTION_SPLIT__NO_SPECIAL_OPTIONS 13
#define T101_INNER_OUTER_OPTION_SPLIT__WITH_OBSERVE_NOTIFICATION 14
#define T102_INNER_OUTER_OPTION_SPLIT__WITH_OBSERVE_REGISTRATION 15
#define T103_OSCORE_PKG_GENERATE__REQUEST_WITH_OBSERVE_REGISTRATION 16
#define T104_OSCORE_PKG_GENERATE__REQUEST_WITH_OBSERVE_NOTIFICATION 17
#define T105_INNER_OUTER_OPTION_SPLIT__TOO_MANY_OPTIONS 18
#define T106_OSCORE_OPTION_GENERATE_NO_PIV 19
#define T200_OPTIONS_SERIALIZE_DESERIALIZE 20
#define T201_COAP_SERIALIZE_DESERIALIZE 21
#define T202_OPTIONS_DESERIALIZE_CORNER_CASES 22
#define T300_OSCORE_OPTION_PARSER_NO_PIV 23
#define T301_OSCORE_OPTION_PARSER_WRONG_N 24
#define T302_OSCORE_OPTION_PARSER_NO_KID 25
#define T303_OPTIONS_REORDER 26
#define T400_IS_CLASS_E 27
#define T401_CACHE_ECHO_VAL 28
#define T402_ECHO_VAL_IS_FRESH 29
#define T500_OSCORE_CONTEXT_INIT_CORNER_CASES 30
#define T501_PIV2SSN 31
#define T502_SSN2PIV 32
#define T503_DERIVE_CORNER_CASE 33
#define T600_SERVER_REPLAY_INIT_TEST 34
#define T601_SERVER_REPLAY_REINIT_TEST 35
#define T602_SERVER_REPLAY_CHECK_AT_START_TEST 36
#define T603_SERVER_REPLAY_CHECK_IN_PROGRESS_TEST 37
#define T604_SERVER_REPLAY_INSERT_ZERO_TEST 38
#define T605_SERVER_REPLAY_INSERT_TEST 39
#define T606_SERVER_REPLAY_STANDARD_SCENARIO_TEST 40
#define T800_OSCORE_LATENCY_TEST 41
#define TEST_EDHOC_INITIATOR_X509_X5T_RFC9529 42
#define TEST_EDHOC_RESPONDER_X509_X5T_RFC9529 43

// if this macro is defined all tests will be executed
#define EXECUTE_ALL_TESTS

// in order to execute only a specific tes set this macro to a specific
// test macro and comment out EXECUTE_ALL_TESTS
#define EXECUTE_ONLY_TEST TEST_EDHOC_INITIATOR_X509_X5T_RFC9529

/**
 * @brief       This function allows to skip a given test if only one other test 
 *              needs to be executed.
 * 
 * @param test_name_macro 
 */
static void skip(int test_name_macro, void (*test_function)())
{
#if !defined EXECUTE_ALL_TESTS
	if (EXECUTE_ONLY_TEST == test_name_macro) {
		test_function();
	} else {
		ztest_test_skip();
	}
#else
	test_function();
#endif
}

ZTEST_SUITE(uoscore_uedhoc, NULL, NULL, NULL, NULL, NULL);

ZTEST(uoscore_uedhoc, test_edhoc_exporter)
{
	skip(TEST_EDHOC_EXPORTER, test_exporter);
};

ZTEST(uoscore_uedhoc, test_initiator_responder_interaction1)
{
	skip(TEST_INITIATOR_RESPONDER_INTERACTION1,
	     t_initiator_responder_interaction1);
};

ZTEST(uoscore_uedhoc, test_initiator_responder_interaction2)
{
	skip(TEST_INITIATOR_RESPONDER_INTERACTION2,
	     t_initiator_responder_interaction2);
};