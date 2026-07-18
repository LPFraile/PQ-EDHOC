/*
 * Copyright (c) 2024 Alexandre Bailon
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(coap);

#include "coap_utils.h"
#include <openthread/platform/radio.h>
#include <string.h>
#include <zephyr/data/json.h>
#include "post.h"

static uint8_t coap_dev_id[COAP_DEVICE_ID_SIZE];

/*static const struct json_obj_descr json_post_data_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct json_post, post_str, JSON_TOK_STRING),
};*/

//#endif /* CONFIG_OT_COAP_SAMPLE_SERVER */

struct post_rsc_data {
	int message_count;
	char post_data[COAP_MAX_BUF_SIZE];
};

/*static const struct json_obj_descr json_post_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct json_post, post_str, JSON_TOK_STRING),
};*/

#ifdef CONFIG_OT_COAP_SAMPLE_CLIENT

static int coap_req_send(const char *addr, const char *uri, uint8_t *buf,
			 int len, otCoapResponseHandler handler, void *ctx,
			 otCoapCode code)
{
	otInstance *ot;
	otMessage *msg;
	otMessageInfo msg_info;
	otError err;
	int ret = 0;

	ot = openthread_get_default_instance();
	if (!ot) {
		LOG_ERR("Failed to get an OpenThread instance");
		printk("ERROR:Failed to get an OpenThread instance\n");
		return -ENODEV;
	}

	memset(&msg_info, 0, sizeof(msg_info));
	otIp6AddressFromString(addr, &msg_info.mPeerAddr);
	msg_info.mPeerPort = OT_DEFAULT_COAP_PORT;
	//printf("entering otCoapNewMessage\n");
	msg = otCoapNewMessage(ot, NULL);
	if (!msg) {
		LOG_ERR("Failed to allocate a new CoAP message");
		printk("ERROR:Failed to allocate a new CoAP message\n");
		return -ENOMEM;
	}

	otCoapMessageInit(msg, OT_COAP_TYPE_CONFIRMABLE, code);

	otCoapMessageGenerateToken(msg, OT_COAP_DEFAULT_TOKEN_LENGTH);
	//printf("entering otCoapMessageAppendUriPathOptions\n");
	err = otCoapMessageAppendUriPathOptions(msg, uri);
	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to append uri-path: %s",
			otThreadErrorToString(err));
		ret = -EBADMSG;
		goto err;
	}

	if (len > 1024) {
		//LOG_PRINTK("appending block1 option\n");
		err = otCoapMessageAppendBlock1Option(
			msg,
			0, // aNum  = block number (0 for first block)
			true, // aMore = true if not last block
			OT_COAP_OPTION_BLOCK_SZX_1024 // aSize = block size exponent
		);
		if (err != OT_ERROR_NONE) {
			//LOG_PRINTK("Block 1 append error\n");
			goto err;
		}
	}

	//printf("entering otCoapMessageSetPayloadMarker\n");
	if (len > 0) {
		err = otCoapMessageSetPayloadMarker(msg);
		if (err != OT_ERROR_NONE) {
			LOG_ERR("Failed to set payload marker: %s",
				otThreadErrorToString(err));
			ret = -EBADMSG;
			goto err;
		}
	}

	if (len <= 1024 && len > 0) {
		//LOG_PRINTK("appending payload no block1\n");
		err = otMessageAppend(msg, buf, len);
		if (err != OT_ERROR_NONE) {
			LOG_ERR("Failed to set append payload to response: %s",
				otThreadErrorToString(err));
			ret = -EBADMSG;
			goto err;
		}

		if (ctx) {
        ((struct post_ctx *)ctx)->len = 0;
    }
	}

	const uint8_t *token = otCoapMessageGetToken(msg);
	uint8_t token_len = otCoapMessageGetTokenLength(msg);
/*
	printk("message TOKEN: ");
	for (int i = 0; i < token_len; i++) {
    	// Print each byte as a 2-digit hex number with leading zeros
    	printk("%02x", token[i]); 
	}
	printk("\n");*/

	((struct post_ctx *)ctx)->msg = msg;

	//LOG_PRINTK("sending with blockwise\n");
	//if (len > 1024) {
	//PRINT_ARRAY("buf", ctx->buf, 2);
	//PRINT_ARRAY("buf", ctx->buf + ctx->len - 2, 2);
	//LOG_PRINTK("befor otCoapSendRequestBlockWise ctx len:%d\n", ctx->len);
	otCoapTxParameters tx_params = {0};
	tx_params.mAckTimeout = 5000;
	tx_params.mAckRandomFactorNumerator = 3;
    tx_params.mAckRandomFactorDenominator = 2;
	tx_params.mMaxRetransmit = 5;
	err = otCoapSendRequestBlockWiseWithParameters(ot, msg, &msg_info, handler, ctx, &tx_params,
					 hook_tx, hook_rx);
	//} else {
	//	err = otCoapSendRequest(ot, msg, &msg_info, handler, ctx);
	//}
	//LOG_PRINTK("later of messga append block1\n");
	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to send the request: %s",
			otThreadErrorToString(err));
		ret = -EIO; /* Find a better error code */
		goto err;
	}

	return 0;

err:
	otMessageFree(msg);
	return ret;
}

#endif /* CONFIG_OT_COAP_SAMPLE_CLIENT */

int coap_post_req_send(const char *addr, const char *uri, uint8_t *buf, int len,
		       otCoapResponseHandler handler, void *ctx)
{
	return coap_req_send(addr, uri, buf, len, handler, ctx,
			     OT_COAP_CODE_POST);
}

#ifdef CONFIG_OT_COAP_SAMPLE_SERVER

int coap_resp_send(otMessage *req, const otMessageInfo *req_info, uint8_t *buf,
		   int len)
{
	otInstance *ot;
	otMessage *resp;
	otCoapCode resp_code;
	otCoapType resp_type;
	otError err;
	int ret;
	//LOG_PRINTK("coap_resp_send: %.*s\n", len, buf);
	ot = openthread_get_default_instance();
	if (!ot) {
		LOG_ERR("Failed to get an OpenThread instance");
		return -ENODEV;
	}

	resp = otCoapNewMessage(ot, NULL);
	if (!resp) {
		LOG_ERR("Failed to allocate a new CoAP message");
		return -ENOMEM;
	}

	switch (otCoapMessageGetType(req)) {
	case OT_COAP_TYPE_CONFIRMABLE:
		resp_type = OT_COAP_TYPE_ACKNOWLEDGMENT;
		break;
	case OT_COAP_TYPE_NON_CONFIRMABLE:
		resp_type = OT_COAP_TYPE_NON_CONFIRMABLE;
		break;
	default:
		LOG_ERR("Invalid message type");
		ret = -EINVAL;
		goto err;
	}

	switch (otCoapMessageGetCode(req)) {
	case OT_COAP_CODE_GET:
		resp_code = OT_COAP_CODE_CONTENT;
		break;
	case OT_COAP_CODE_PUT:
		resp_code = OT_COAP_CODE_CHANGED;
		break;
	case OT_COAP_CODE_POST:
		resp_code = OT_COAP_CODE_CHANGED;
		break;
	default:
		LOG_ERR("Invalid message code");
		//LOG_PRINTK("message code:%d", otCoapMessageGetCode(req));
		ret = -EINVAL;
		goto err;
	}

	err = otCoapMessageInitResponse(resp, req, resp_type, resp_code);
	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to initialize the response: %s",
			otThreadErrorToString(err));
		ret = -EBADMSG;
		goto err;
	}
	//LOG_PRINTK("len inside coap_resp_send: %d\n", len);
	if (len > 1024) {
		//LOG_PRINTK("appending block2 option\n");
		err = otCoapMessageAppendBlock2Option(
			resp, 0, (len > 1024), OT_COAP_OPTION_BLOCK_SZX_1024);
		if (err != OT_ERROR_NONE) {
			LOG_ERR("Failed to append Block2 option: %s",
				otThreadErrorToString(err));
			ret = -EBADMSG;
			goto err;
		}
	}
	err = otCoapMessageSetPayloadMarker(resp);
	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to set payload marker: %s",
			otThreadErrorToString(err));
		ret = -EBADMSG;
		goto err;
	}

	if (len <= 1024) {
		//LOG_PRINTK("appending payload no block2\n");
		err = otMessageAppend(resp, buf, len);
		if (err != OT_ERROR_NONE) {
			LOG_ERR("Failed to set append payload to response: %s",
				otThreadErrorToString(err));
			ret = -EBADMSG;
			goto err;
		}
	}

	//do not like this
	server_post_ctx.len = len;
	server_post_ctx.buf = buf;
	otCoapTxParameters tx_params = {0};
	tx_params.mAckTimeout = 5000;
	tx_params.mAckRandomFactorNumerator = 3;
    tx_params.mAckRandomFactorDenominator = 2;
	tx_params.mMaxRetransmit = 5;
	if (len > 1024) {
		
		//LOG_PRINTK("sending response with blockwise\n");
		//PRINT_ARRAY("first 2 bytes of resp buf before otCoapSendResponceBlockWise", server_post_ctx.buf, 2);
		//PRINT_ARRAY("last 2 bytes of resp buf before otCoapSendResponceBlockWise", server_post_ctx.buf + server_post_ctx.len - 2, 2);
		//LOG_PRINTK("len before otCoapSendResponseBlockWise: %d\n", server_post_ctx.len);
		const uint8_t *token = otCoapMessageGetToken(resp);
		uint8_t token_len = otCoapMessageGetTokenLength(resp);
/*
		printk("message TOKEN: ");
		for (int i = 0; i < token_len; i++) {
    		// Print each byte as a 2-digit hex number with leading zeros
    		printk("%02x", token[i]); 
		}
		printk("\n");*/
		err = otCoapSendResponseBlockWiseWithParameters(ot, resp, req_info, &tx_params, &server_post_ctx,
						  hook_tx);
	} else {
		//LOG_PRINTK("sending response without blockwise\n");
		err = otCoapSendResponseWithParameters(ot, resp, req_info, &tx_params);
	}

	//otMessageFree(resp);
	//k_sleep(K_SECONDS(2));

	//err = otCoapSendResponse(ot, resp, req_info);
	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to send the response: %s",
			otThreadErrorToString(err));
		ret = -EIO;
		goto err;
	}

	return 0;

err:
	otMessageFree(resp);
	return ret;
}

#endif /* CONFIG_OT_COAP_SAMPLE_SERVER */

int coap_req_handler(void *ctx, otMessage *msg, const otMessageInfo *msg_info,
		     coap_req_handler_put put_fn, coap_req_handler_get get_fn,
		     coap_req_handler_post post_fn)
{

	struct post_ctx *my_ctx = (struct post_ctx *)ctx;
	//LOG_PRINTK("+=+=+=+=+=+=+=+=+=+=MESSAGE=+=+=+=+=+=+=+=+=+=+\n");
	//LOG_PRINTK("START len post: %d\n", my_ctx->len);
	//LOG_PRINTK("START SERVER post:");
	/*	PRINT_ARRAY("coap_buf_msg_in", coap_buf_msg_in,
		    my_ctx->len);
*/
	//PRINT_ARRAY("POST Payload start", my_ctx->buf, 2);
	//PRINT_ARRAY("POST Payload end", my_ctx->buf + my_ctx->len - 2,
	//	    2);
	//LOG_PRINTK("POST Payload len:%d\n", my_ctx->len);

	//LOG_PRINTK("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n\n");
	//int num = otCoapMessageGetBlockWiseBlockNumber(msg);
	otCoapCode msg_code = otCoapMessageGetCode(msg);
	otCoapType msg_type =
		otCoapMessageGetType(msg); // if typo, keep original
	int ret = 0;

	//LOG_PRINTK("message type: %d\n", msg_code);

	if (msg_type != OT_COAP_TYPE_CONFIRMABLE &&
	    msg_type != OT_COAP_TYPE_NON_CONFIRMABLE) {
		//LOG_PRINTK("exiting req handler confirmable out\n");
		return -EINVAL;
	}

	if (msg_code == OT_COAP_CODE_POST && post_fn) {
		//printk("received post message\n");
		//printk("msg_in_util_len inside req handler post: %d\n",
		//       my_ctx->len);
		int len = otMessageGetLength(msg) - otMessageGetOffset(msg);
		//printk("len inside req handler post: %d\n", len);
		/*if (len < 1024){
			my_ctx->len = 0;
		}*/
		if (len >= COAP_ENTIRE_MESSAGE_SIZE) {
			len = COAP_ENTIRE_MESSAGE_SIZE - 1;
		}
		//LOG_PRINTK("into_rx_flag:%d\n", into_rx_flag);
		if(!into_rx_flag){
			my_ctx->len = 0;
		}
			into_rx_flag = 0;
		if (my_ctx->len == 0) {
			my_ctx->len = len;
			//LOG_PRINTK("my_ctx->len == 0\n");
			otMessageRead(msg, otMessageGetOffset(msg),
				      my_ctx->buf, my_ctx->len);

			//LOG_PRINTK(
			//	"+=+=+=+=+=+=+=+=+=+=MESSAGE=+=+=+=+=+=+=+=+=+=+\n");
			//LOG_PRINTK("ACK Payload length msg (%zu bytes)\n",
			//	   my_ctx->len);
			//print_in_chunks(g_rx_buf, len, 256);
			//LOG_PRINTK("POST payload: %s\n", g_rx_buf);
			//PRINT_ARRAY("ACK Payload start", my_ctx->buf, 2);
			//PRINT_ARRAY("ACK Payload end",
			//	    my_ctx->buf + my_ctx->len - 2, 2);

			//LOG_PRINTK(
			//	"+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
		}

		if (msg_type == OT_COAP_TYPE_CONFIRMABLE) {
			//LOG_PRINTK("OT_COAP_TYPE_CONFIRMABLE\n");
			ret = post_fn(my_ctx, msg, msg_info);
			LOG_PRINTK("%s\n\n\n",
				   ret ? "could not send ack" : "ack sent");
		} else {
			//LOG_PRINTK("OT_COAP_TYPE_NONCONFIRMABLE\n\n\n");
		}
		return ret;
	}

	//LOG_PRINTK("exiting req handler end\n\n");
	return -EINVAL;
}

const char *coap_device_id(void)
{
	otInstance *ot = openthread_get_default_instance();
	otExtAddress eui64;
	int i;

	if (coap_dev_id[0] != '\0') {
		return coap_dev_id;
	}

	otPlatRadioGetIeeeEui64(ot, eui64.m8);
	for (i = 0; i < 8; i++) {
		if (i * 2 >= COAP_DEVICE_ID_SIZE) {
			i = COAP_DEVICE_ID_SIZE - 1;
			break;
		}
		sprintf(coap_dev_id + i * 2, "%02x", eui64.m8[i]);
	}
	coap_dev_id[i * 2] = '\0';

	return coap_dev_id;
}

int coap_init(void)
{
	otError err;
	otInstance *ot;

#ifdef CONFIG_OT_COAP_SAMPLE_SERVER
	printk("Initializing OpenThread CoAP server\n");
#else
	printk("Initializing OpenThread CoAP client\n");
#endif
	ot = openthread_get_default_instance();
	if (!ot) {
		LOG_ERR("Failed to get an OpenThread instance");
		printk("ERROR:Failed to get an OpenThread instance\n");
		return -ENODEV;
	}

	err = otCoapStart(ot, OT_DEFAULT_COAP_PORT);
	if (err != OT_ERROR_NONE) {
		LOG_ERR("Cannot start CoAP: %s", otThreadErrorToString(err));
		printk("ERROR:Cannot start CoAP: %s\n",
		       otThreadErrorToString(err));
		return -EBADMSG;
	} else {
		printk("coap initialized\n");
	}
	return 0;
}
