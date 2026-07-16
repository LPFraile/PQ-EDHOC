
#define COAP_ENTIRE_MESSAGE_SIZE 8192

#include <zephyr/net/openthread.h>
#include <openthread/coap.h>
#define POST_URI "post_data"


// Add this definition:
#define PRINT_ARRAY(label, buf, len)                                           \
	do {                                                                   \
		LOG_PRINTK("%s: ", label);                                     \
		for (size_t i = 0; i < (len); i++) {                           \
			LOG_PRINTK("%02x ", (buf)[i]);                         \
		}                                                              \
		LOG_PRINTK("\n");                                              \
	} while (0)

/*
struct buf_utils {
	uint8_t *buf;
	uint16_t len;
	uint16_t max_len;
};
*/

extern bool into_rx_flag;

#ifdef CONFIG_OT_COAP_SAMPLE_CLIENT

struct post_ctx{
	uint8_t *buf;
	uint16_t len;
	struct k_sem *sem;
	bool last_message;
	otMessage *msg;
};

#endif /* CONFIG_OT_COAP_SAMPLE_CLIENT */


#ifdef CONFIG_OT_COAP_SAMPLE_SERVER

struct post_ctx{
	uint8_t *buf;
	uint16_t len;
	struct k_sem *post_uedhoc_wait_sem;
	struct k_sem *rx_wait_sem;
	bool no_more_message;
};

#endif /* CONFIG_OT_COAP_SAMPLE_SERVER */

extern uint8_t coap_buf_msg[COAP_ENTIRE_MESSAGE_SIZE];

/*
extern struct buf_utils msg_in_utils;
extern struct buf_utils msg_out_utils;
extern uint8_t coap_buf_msg_out[COAP_ENTIRE_MESSAGE_SIZE];
extern uint8_t coap_buf_msg_in[COAP_ENTIRE_MESSAGE_SIZE];
*/

otError hook_rx(void *aContext, const uint8_t *aBlock, uint32_t aPosition,
		uint16_t aBlockLength, bool aMore, uint32_t aTotalLength);

otError hook_tx(void *aContext, uint8_t *aBlock, uint32_t aPosition,
		uint16_t *aBlockLength, bool *aMore);

int send_post(const char *payload, char *addr, char *uri, void *ctx);

#ifdef CONFIG_OT_COAP_SAMPLE_SERVER
void coap_post_reg_rsc(void);
#endif /* CONFIG_OT_COAP_SAMPLE_SERVER */
