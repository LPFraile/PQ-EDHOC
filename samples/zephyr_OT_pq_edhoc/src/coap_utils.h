/*
 * Copyright (c) 2024 Alexandre Bailon
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef COAP_UTILS_H
#define COAP_UTILS_H

#include <zephyr/net/openthread.h>
#include <openthread/coap.h>

#define COAP_MAX_BUF_SIZE 128
#define COAP_ENTIRE_MESSAGE_SIZE 4096
#define COAP_DEVICE_ID_SIZE 25

#ifdef CONFIG_OT_COAP_SAMPLE_SERVER
extern struct post_ctx server_post_ctx;
#endif /* CONFIG_OT_COAP_SAMPLE_SERVER */

typedef int (*coap_req_handler_put)(void *ctx, uint8_t *buf, int size);
typedef int (*coap_req_handler_get)(void *ctx, otMessage *msg,
				    const otMessageInfo *msg_info);
typedef int (*coap_req_handler_post)(void *ctx, otMessage *msg,
				     const otMessageInfo *msg_info);

int post_uedhoc(void *ctx, otMessage *msg, const otMessageInfo *msg_info);

void print_in_chunks(const uint8_t *buf, size_t len, size_t chunk_size);

void coap_post_req_cb(void *ctx, otMessage *msg, const otMessageInfo *msg_info,
		      otError error);

int coap_init(void);
int coap_req_handler(void *ctx, otMessage *msg, const otMessageInfo *msg_info,
		     coap_req_handler_put put_fn, coap_req_handler_get get_fn,
		     coap_req_handler_post post_fn);
int coap_resp_send(otMessage *req, const otMessageInfo *req_info, uint8_t *buf,
		   int len);
int coap_post_req_send(const char *addr, const char *uri, uint8_t *buf, int len,
		       otCoapResponseHandler handler, void *ctx);
const char *coap_device_id(void);

#endif /* COAP_UTILS_H */
