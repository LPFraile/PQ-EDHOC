
#include <errno.h>
#include <stdio.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(coap);

#include "coap_utils.h"
#include "post.h"
#include <openthread/platform/radio.h>
#include <string.h>
#include <zephyr/data/json.h>

/*
uint8_t coap_buf_msg_in[COAP_ENTIRE_MESSAGE_SIZE];
uint8_t coap_buf_msg_out[COAP_ENTIRE_MESSAGE_SIZE];

struct buf_utils msg_in_utils = { .buf = coap_buf_msg_in,
				  .len = 0,
				  .max_len = COAP_ENTIRE_MESSAGE_SIZE };

struct buf_utils msg_out_utils = { .buf = coap_buf_msg_out,
				   .len = 0,
				   .max_len = COAP_ENTIRE_MESSAGE_SIZE };
*/

bool into_rx_flag = 0;
uint8_t counter = 0;
#ifdef CONFIG_OT_COAP_SAMPLE_CLIENT

void coap_post_req_cb(void *ctx, otMessage *msg, const otMessageInfo *msg_info,
		      otError error)
{

	struct post_ctx *my_ctx = (struct post_ctx *)ctx;
    counter++;
	
    printk("counter %d \n", counter);
    end_messaging = k_cycle_get_32();
	if (my_ctx->last_message){
	
		return;
	}

		//LOG_PRINTK("post_callback\n");
	if (error != OT_ERROR_NONE || msg == NULL) {
		LOG_PRINTK("post_callback: error=%d, msg=%p\n", error,
			   (void *)msg);
		return;
	}

	//memset(coap_buf_msg_out, 0, msg_out_utils.len);
	//msg_out_utils.len = 0;

	//LOG_PRINTK("+=+=+=+=+=+=+=+=+=+=MESSAGE=+=+=+=+=+=+=+=+=+=+\n");
	//LOG_PRINTK("CLIENT post_callback:\n");

	//PRINT_ARRAY("ACK Payload start", my_ctx->buf, 2);
	//PRINT_ARRAY("ACK Payload end", my_ctx->buf + my_ctx->len - 2,
	//	    2);
	//LOG_PRINTK("ACK Payload len:%d\n", my_ctx->len);
	//LOG_PRINTK("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n\n");
	if (my_ctx->len == 0) {
		//LOG_PRINTK("len=0\n");
		int len = otMessageGetLength(msg) - otMessageGetOffset(msg);
		my_ctx->len = len;
		if (len < 0) {
			//LOG_PRINTK("post_callback: invalid len\n");
			return;
		}
		if (len >= COAP_ENTIRE_MESSAGE_SIZE) {
			len = COAP_ENTIRE_MESSAGE_SIZE - 1;
		}
		otMessageRead(msg, otMessageGetOffset(msg), my_ctx->buf,
			      my_ctx->len);
	}
	//LOG_PRINTK("+=+=+=+=+=+=+=+=+=+=MESSAGE=+=+=+=+=+=+=+=+=+=+\n");
	//LOG_PRINTK("CLIENT post_callback:\n");
	/*PRINT_ARRAY("post_callback data", coap_buf_msg_in,
		    my_ctx->len);*/
	//PRINT_ARRAY("ACK Payload start", my_ctx->buf, 2);
	//PRINT_ARRAY("ACK Payload end", my_ctx->buf + my_ctx->len - 2,
	//	    2);
	//LOG_PRINTK("ACK Payload len:%d\n", my_ctx->len);
	//LOG_PRINTK("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n\n");

	if (my_ctx->sem) {
        //LOG_PRINTK("Signaling main thread...\n");
        k_sem_give(my_ctx->sem);
    }
	//LOG_PRINTK("post_callback len: %d\n", my_ctx->len);
}

#endif /* CONFIG_OT_COAP_SAMPLE_CLIENT */

otError hook_rx(void *aContext, const uint8_t *aBlock, uint32_t aPosition,
		uint16_t aBlockLength, bool aMore, uint32_t aTotalLength)
{
#ifdef CONFIG_OT_COAP_SAMPLE_SERVER
	//LOG_PRINTK("SERVER\n");
#endif

#ifdef CONFIG_OT_COAP_SAMPLE_CLIENT
	//LOG_PRINTK("CLIENT\n");
#endif

	//printk("===> hook_rx invoked <===\n");
	//printk("[RX] pos=%u len=%u more=%d total=%u\n\n", aPosition,
	//       aBlockLength, aMore, aTotalLength);

	struct post_ctx *my_ctx = (struct post_ctx *)aContext;

	// A. Safety Check (Prevent Overflow of Global Buffer)
	if ((size_t)aPosition + (size_t)aBlockLength > COAP_ENTIRE_MESSAGE_SIZE) {
		LOG_ERR("Error: Incoming block-wise data too big for coap_buf_msg_in!");
		return OT_ERROR_NO_BUFS;
	}

	// B. Copy DIRECTLY from OpenThread block buffer to global reassembly buffer
	memcpy(my_ctx->buf + aPosition, aBlock, aBlockLength);
	size_t new_len = (size_t)aPosition + (size_t)aBlockLength;
	if (new_len > (size_t)my_ctx->len) {
		my_ctx->len = (int)new_len;
	}
	//LOG_PRINTK("[RX Hook] Received Slice: Pos %d, Len %d\n", aPosition,
	//	   aBlockLength);

	//LOG_PRINTK("=+=+=+=+=+=+=+=+=+=+=MESSAGE=+=+=+=+=+=+=+=+=+=+\n");
	//PRINT_ARRAY("RX Hook Payload start", aBlock, 2);
	//PRINT_ARRAY("RX Hook Payload end", aBlock + aBlockLength - 2, 2);
	//LOG_PRINTK("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=++=+=+=+=+=+=+=+=+=+\n");
	// C. Detect End of Transfer (just for logging/debug here)
	if (aMore == false) {
		// Ensure null-termination just in case
		//s_server_reassembly_buf[aPosition + aBlockLength] = '\0';
		into_rx_flag = 1;
		//LOG_PRINTK(
		//	">> Block-wise Transfer Complete! Total Bytes: %d <<\n",
		//	my_ctx->len);
	}
	return OT_ERROR_NONE;
}

otError hook_tx(void *aContext, uint8_t *aBlock, uint32_t aPosition,
		uint16_t *aBlockLength, bool *aMore)
{
#ifdef CONFIG_OT_COAP_SAMPLE_SERVER
	//LOG_PRINTK("SERVER\n");
#endif

#ifdef CONFIG_OT_COAP_SAMPLE_CLIENT
	//LOG_PRINTK("CLIENT\n");
#endif

	//LOG_PRINTK("aContext:%p\n", aContext);
	struct post_ctx *my_ctx = (struct post_ctx *)aContext;
/*	LOG_PRINTK("my_ctx len:%d\n", my_ctx->len);
	PRINT_ARRAY("my_ctx buf start", my_ctx->buf, 2);
	PRINT_ARRAY("my_ctx buf end", my_ctx->buf + my_ctx->len - 2, 2);*/
	// B. Check if we have reached the end of the data
	if (aPosition >= my_ctx->len) {
		*aBlockLength = 0;
		*aMore = false;
		aPosition = 0;
		return OT_ERROR_NONE;
	}

	// C. Calculate remaining data
	uint32_t remaining = my_ctx->len - aPosition;

	// D. Negotiate Block Size
	uint16_t maxLen = *aBlockLength;
	uint16_t toCopy = (remaining < maxLen) ? (uint16_t)remaining : maxLen;

	// E. Copy DIRECTLY from global post_str into the OpenThread block buffer
	memcpy(aBlock, (void *)(my_ctx->buf + aPosition), toCopy);

	// Tell OT how many bytes we actually wrote
	*aBlockLength = toCopy;

	// Decide if another block is needed
	*aMore = ((uint32_t)aPosition + toCopy < my_ctx->len);

	//check this
	if (*aMore == 0){
		my_ctx->len = 0;
	}

	//LOG_PRINTK("=+=+=+=+=+=+=+=+=+=+=MESSAGE=+=+=+=+=+=+=+=+=+=+\n");
	//PRINT_ARRAY("TX Hook Payload start", aBlock, 2);
	//PRINT_ARRAY("TX Hook Payload end", aBlock + *aBlockLength - 2, 2);
	//LOG_PRINTK("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=++=+=+=+=+=+=+=+=+=+\n");
		
	//printk("===> hook_tx invoked <===\n");
	//LOG_PRINTK("[TX Hook] Sending Slice: Pos %d, Len %d, More %d\n\n",
	//	   aPosition, *aBlockLength, *aMore);
	return OT_ERROR_NONE;
}

#ifdef CONFIG_OT_COAP_SAMPLE_SERVER

int post_uedhoc(void *ctx, otMessage *msg, const otMessageInfo *msg_info)
{
	int ret = 0;

	//LOG_PRINTK("in post_uedhoc\n\n");

	struct post_ctx *my_ctx = (struct post_ctx *)ctx;

	k_sem_give(my_ctx->rx_wait_sem);

	//LOG_PRINTK("uedhoc wait\n");
	k_sem_reset(my_ctx->post_uedhoc_wait_sem);
	ret = k_sem_take(my_ctx->post_uedhoc_wait_sem, K_SECONDS(10));
	//LOG_PRINTK("after take post_uedhoc_wait_sem\n");

	if(my_ctx->no_more_message == 1){
		//memcpy(my_ctx->buf, NULL, 
		my_ctx->len = 0;
	}

/*
	//len of bellow 58
	snprintf(my_ctx->buf, COAP_ENTIRE_MESSAGE_SIZE,
		 "message_2222222222222222222222222222222222222222222222221");
*/

	//len of bellow 311
	/*snprintf(
		my_ctx->buf, COAP_ENTIRE_MESSAGE_SIZE,
		"message_22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221");
*/
	/*
	//len of bellow 3748
	snprintf(
		my_ctx->buf, COAP_ENTIRE_MESSAGE_SIZE,
		"message_2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221");
*/
/*
	//len of bellow 1264
	snprintf(
		my_ctx->buf, COAP_ENTIRE_MESSAGE_SIZE,
		"message_2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222221");
*/
	//msg_out_utils.buf = coap_buf_msg_out;
	//my_ctx->len = strlen(my_ctx->buf);
	//PRINT_ARRAY("Callback Payload start", my_ctx->buf, 2);
	//PRINT_ARRAY("Callback Payload end",
	//	    my_ctx->buf + my_ctx->len - 2, 2);
	//LOG_PRINTK("Callback Payload len:%d\n", my_ctx->len);
	ret = coap_resp_send(msg, msg_info, my_ctx->buf,
			      my_ctx->len);
/*	if (ret != 0){
		LOG_PRINTK("coap_resp_send failed!\n");
		return ret;
	}

	my_ctx->len = 0;
*/
	return 0;
}

void post_handler(void *ctx, otMessage *msg, const otMessageInfo *msg_info)
{

	const uint8_t *token = otCoapMessageGetToken(msg);
	uint8_t token_len = otCoapMessageGetTokenLength(msg);

	/*printk("CoAP TOKEN: ");
	for (int i = 0; i < token_len; i++) {
    	// Print each byte as a 2-digit hex number with leading zeros
    	printk("%02x", token[i]); 
	}
	printk("\n");*/


	coap_req_handler(ctx, msg, msg_info, NULL, NULL, post_uedhoc);

	struct post_ctx *my_ctx = (struct post_ctx *)ctx;
	//LOG_PRINTK("finish post_handler\n");
	//PRINT_ARRAY("post_handler Payload start", my_ctx->buf, 2);
	//PRINT_ARRAY("post_handler Payload end",
	//	    my_ctx->buf + my_ctx->len - 2, 2);
	//LOG_PRINTK("post_handler Payload len:%d\n", my_ctx->len);
}

K_SEM_DEFINE(rx_wait_sem, 0, 1);
K_SEM_DEFINE(post_uedhoc_wait_sem, 0, 1);

struct post_ctx server_post_ctx = {
	.buf = coap_buf_msg,
	.len = 0,
	.rx_wait_sem = &rx_wait_sem,
	.post_uedhoc_wait_sem = &post_uedhoc_wait_sem,
};

static otCoapBlockwiseResource post_data = {
	.mUriPath = POST_URI,
	.mHandler = post_handler,
	.mContext = &server_post_ctx,
	.mNext = NULL,
	.mReceiveHook = hook_rx,
	.mTransmitHook = hook_tx,
};

void coap_post_reg_rsc(void)
{
	otInstance *ot = openthread_get_default_instance();
	//LOG_PRINTK("Registering CoAP POST resource\n");
	//LOG_PRINTK("post_data.mContext:%p\n", post_data.mContext);

	otCoapAddBlockWiseResource(ot, &post_data);
}

#endif /* CONFIG_OT_COAP_SAMPLE_SERVER */

#ifdef CONFIG_OT_COAP_SAMPLE_CLIENT

int send_post(const char *payload, char *addr, char *uri, void *ctx)
//int send_post(const char *payload)
{
	//LOG_PRINTK("in send_post\n");
	//LOG_PRINTK("addr:%s\n", addr);
	//LOG_PRINTK("uri:%s\n", uri);

	int err = 0;

	/*size_t payload_len = strlen(payload) + 1;
	LOG_PRINTK("payload_len: %zu\n", payload_len);

	if (payload_len >= COAP_ENTIRE_MESSAGE_SIZE) {
		LOG_ERR("Payload too large: %zu bytes (max %d)", payload_len,
			COAP_ENTIRE_MESSAGE_SIZE - 1);
		return -1;
	}
	*/

	struct post_ctx *my_ctx = (struct post_ctx *)ctx;

	//memcpy(my_ctx->buf, payload, payload_len);
	//my_ctx->len = (uint16_t)payload_len;

	//LOG_PRINTK("sending post message (%zu bytes)\n", payload_len);
	//LOG_PRINTK("my_ctx->len:%d\n", my_ctx->len);
	//LOG_PRINTK("post_str:%.*s\n",strlen(post_str), post_str);
	//print_in_chunks(post_str, payload_len, 256);

	// Pass post_str (not &post_str), and include null terminator in length
	err = coap_post_req_send(addr, uri, payload, my_ctx->len,
				 coap_post_req_cb, my_ctx);

	if (err != 0) {
		LOG_ERR("coap_post_req_send failed: %d", err);
		return -1;
	}

	return 0;
}

#endif /* CONFIG_OT_COAP_SAMPLE_CLIENT */
