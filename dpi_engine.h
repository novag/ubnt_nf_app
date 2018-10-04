#include <linux/skbuff.h>

#define SW_APP   (1 << 1)

#define TDTS_RES_TYPE_APPID  SW_APP

#define SW_FG_FINAL  0x0001	/* final */
#define SW_FG_NOTIA  0x0002	/* no interest (deprecated) */
#define SW_FG_NOINT  SW_FG_NOTIA	/* no interest */
#define SW_FG_NOMORE 0x0004	/* no more */

#define TDTS_DEVID_MAX_HOST_NAME_LEN 32

typedef struct {
	char *name;		// Attack name
	char *cat_name;		// Attack category name

	uint32_t rule_id;	// Rule ID

//      unsigned short cat_id; // Attack category ID
	uint16_t cat_id;	// Attack category ID

	uint8_t proto;		// Protocol
	uint8_t severity;	// Severity
} tdts_ips_matching_results_t;

typedef struct {
	/*
	 * Under-development.
	 */
} tdts_adp_matching_results_t;

typedef struct {
	char *cat_name;		// Category name
	char *app_name;		// Application name
	char *beh_name;		// Behavior name

	/*
	 * * behinst:
	 *   8 bit     16 bit     8 bit
	 * +-----------------------------+
	 * | cat id |  app id   | beh id |
	 * +-----------------------------+
	 */
	uint8_t cat_id;		// Category ID
	uint16_t app_id;	// Application ID
	uint8_t beh_id;		// Behavior ID

	/* misc */
	uint32_t action;	// Recommended action to take.
	uint32_t fwmark;	// Firewall mark (deprecated)
} tdts_appid_matching_results_t;

typedef struct {
	uint16_t vendor_id;	//!< Vendor ID, e.g. "Microsoft"
	uint16_t name_id;	//!< OS name ID, e.g. "Windows XP"
	uint16_t class_id;	//!< OS class ID, e.g. "Windows Series"
	uint16_t cat_id;	//!< Device Category ID, e.g. "Phone", "TV"
	uint16_t dev_id;	//!< Device Name ID, e.g. "iPhone 4", "Windows Phone"
	uint16_t family_id;	//!< Device family ID, e.g. "Handheld family", etc.

	/* It's recommended to pick-up the higher prio rule. */
	uint16_t prio;		//!< Priority of matched rule (0: highest prio, 65535: lowest prio).

	unsigned char host_name[TDTS_DEVID_MAX_HOST_NAME_LEN];	//!< Detected device host name in DHCP (if any).
} tdts_devid_matching_results_t;

typedef struct {
	char *domain;
	unsigned domain_len;
	char *path;
	unsigned path_len;
	char *referer;
	unsigned referer_len;

	char cat[4];
	char score;
	char hook;
	unsigned char *mac;
	unsigned char act;
} tdts_url_matching_results_t;

typedef struct {
	unsigned short type;
	unsigned short flags;

	int pkt_decoder_verdict;

	tdts_ips_matching_results_t ips;
	tdts_appid_matching_results_t appid;
	tdts_devid_matching_results_t devid;
	tdts_url_matching_results_t url;
	tdts_adp_matching_results_t adp;

} tdts_pkt_matching_results_t;

typedef enum {
	TDTS_PKT_PARAMETER_PKT_TYPE_NONE = 0,
	TDTS_PKT_PARAMETER_PKT_TYPE_L2_ETHERNET,
	TDTS_PKT_PARAMETER_PKT_TYPE_L3_IP,
	TDTS_PKT_PARAMETER_PKT_TYPE_L3_IP6,
	TDTS_PKT_PARAMETER_PKT_TYPE_MAX
} tdts_pkt_parameter_pkt_type_t;

typedef struct pkt_parameter {
	/*
	 * Callers' arguments to pass to TDTS.
	 */
	unsigned short req_flag;
	unsigned short reserved;

	tdts_pkt_parameter_pkt_type_t pkt_type;
	void *pkt_ptr;
	unsigned pkt_len;
	unsigned long pkt_time_sec;

	char hook;
	char cat[4];
	struct pkt_parameter *(*async_prepare) (struct pkt_parameter *);
	int (*async_send) (struct pkt_parameter *);
	void *private_ptr;

	/*
	 * TDTS response for callers to read.
	 */
	tdts_pkt_matching_results_t results;
} tdts_pkt_parameter_t;

#define IS_FLAGS_FINAL(__sw) ((__sw)->flags & SW_FG_FINAL)
#define IS_FLAGS_NOINT(__sw) ((__sw)->flags & SW_FG_NOINT)
#define IS_FLAGS_NOMORE(__sw) ((__sw)->flags & SW_FG_NOMORE)

/*
 * APPID results
 */
#define TDTS_PKT_PARAMETER_RES_APPID(_param) (&((_param)->results.appid))
#define TDTS_PKT_PARAMETER_RES_APPID_CAT_ID(__param)   TDTS_PKT_PARAMETER_RES_APPID(__param)->cat_id
#define TDTS_PKT_PARAMETER_RES_APPID_CAT_NAME(__param) TDTS_PKT_PARAMETER_RES_APPID(__param)->cat_name
#define TDTS_PKT_PARAMETER_RES_APPID_APP_ID(__param)   TDTS_PKT_PARAMETER_RES_APPID(__param)->app_id
#define TDTS_PKT_PARAMETER_RES_APPID_APP_NAME(__param) TDTS_PKT_PARAMETER_RES_APPID(__param)->app_name
#define TDTS_PKT_PARAMETER_RES_APPID_BEH_ID(__param)   TDTS_PKT_PARAMETER_RES_APPID(__param)->beh_id
#define TDTS_PKT_PARAMETER_RES_APPID_BEH_NAME(__param) TDTS_PKT_PARAMETER_RES_APPID(__param)->beh_name
#define TDTS_PKT_PARAMETER_RES_APPID_ACTION(__param)   TDTS_PKT_PARAMETER_RES_APPID(__param)->action
#define TDTS_PKT_PARAMETER_RES_APPID_FWMARK(__param)   TDTS_PKT_PARAMETER_RES_APPID(__param)->fwmark

#define TDTS_PKT_PARAMETER_RES_APPID_CHECK_FINAL(__param)  IS_FLAGS_FINAL(&((__param)->results))
#define TDTS_PKT_PARAMETER_RES_APPID_CHECK_NOMORE(__param) IS_FLAGS_NOMORE(&((__param)->results))
#define TDTS_PKT_PARAMETER_RES_APPID_CHECK_NOINT(__param)  IS_FLAGS_NOINT(&((__param)->results))

static inline unsigned short
    __attribute__ ((unused)) tdts_check_pkt_parameter_res(const
							  tdts_pkt_parameter_t *
							  pkt_param,
							  unsigned short
							  res_type)
{
	return (pkt_param->results.type & res_type);
}

#define tdts_init_pkt_matching_results_url(__mr) \
	do { \
		(__mr)->url.domain = NULL; \
		(__mr)->url.domain_len = 0; \
		(__mr)->url.path = NULL; \
		(__mr)->url.path_len = 0; \
		(__mr)->url.referer = NULL; \
		(__mr)->url.referer_len = 0; \
	} while (0)

#define tdts_init_pkt_matching_results(_mr) \
	do { \
		(_mr)->type = 0; \
		(_mr)->flags = 0; \
		tdts_init_pkt_matching_results_url(_mr); \
	} while (0)

/* req flag */
#define tdts_set_pkt_parameter_req_flag(__param, __req_flag) \
	do { \
		(__param)->req_flag = __req_flag; \
	} while (0)
#define tdts_get_pkt_parameter_req_flag(__param) ((__param)->req_flag)

/* pkt time */
#define tdts_set_pkt_parameter_pkt_time(__param, __sec) \
	do { \
		(__param)->pkt_time_sec = (unsigned long) (__sec); \
	} while (0)
#define tdts_get_pkt_parameter_pkt_time(__param, __sec) ((__param)->pkt_time_sec)

/* pkt param */
#define tdts_set_pkt_parameter(_param, _pkt, _pkt_len, _pkt_type) \
	do { \
		(_param)->pkt_type = _pkt_type; \
		(_param)->pkt_ptr = (void *) (_pkt); \
		(_param)->pkt_len = _pkt_len; \
		tdts_init_pkt_matching_results(&((_param)->results)); \
	} while (0)

#define tdts_init_pkt_parameter(___param, ___req_flag, ___pkt_time) \
	do { \
		tdts_set_pkt_parameter(___param, NULL, 0, TDTS_PKT_PARAMETER_PKT_TYPE_NONE); \
		tdts_set_pkt_parameter_req_flag(___param, ___req_flag); \
		tdts_set_pkt_parameter_pkt_time(___param, ___pkt_time); \
	} while (0)

#define tdts_set_pkt_parameter_l3_ip(__param, __pkt, __pkt_len) \
	tdts_set_pkt_parameter(__param, __pkt, __pkt_len, TDTS_PKT_PARAMETER_PKT_TYPE_L3_IP)

#define tdts_set_pkt_parameter_l3_ip6(__param, __pkt, __pkt_len) \
	tdts_set_pkt_parameter(__param, __pkt, __pkt_len, TDTS_PKT_PARAMETER_PKT_TYPE_L3_IP6)

extern int tdts_shell_dpi_l3_skb(struct sk_buff *skb,
				 tdts_pkt_parameter_t * param);
extern int tdts_shell_dpi_l3_data(struct sk_buff *, tdts_pkt_parameter_t *);
