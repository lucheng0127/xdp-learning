//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>

/*
Define XDP_ACTION_MAX as arrary length,
use xdp_action as arrary index to recode
pkt and bytes stats
*/
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

/*
Check for this to optimize code
https://gist.github.com/teknoraver/b66115e3518bb1b7f3e79f52aa2c3424
*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, XDP_ACTION_MAX);
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_stats_map SEC(".maps");

struct datarec {
    __u64 rx_pkts;
    __u64 rx_bytes;
};

static __always_inline
int xdp_stats_record_action(struct xdp_md *ctx, int action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	__u64 bytes = data_end - data;

	rec->rx_pkts++;
	rec->rx_bytes += bytes;

	// Checkout the log via cat cat /sys/kernel/debug/tracing/trace_pipe
	char info_fmt[] = "action %d bytes %d";
	bpf_trace_printk(info_fmt, sizeof(info_fmt), action, bytes);

	return action;
}

struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
				 void *data_end,
				 struct ethhdr **eh)
{
	struct ethhdr *ehdr = nh->pos;
	int hdrsize = sizeof(*ehdr);

	if (nh->pos + hdrsize > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*eh = ehdr;
	return ehdr->h_proto;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				void *data_end,
				struct iphdr **ih)
{
	struct iphdr *ihdr = nh->pos;
	int hdrsize = sizeof(*ihdr);

	if (nh->pos + hdrsize > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*ih = ihdr;
	return ihdr->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
				  void *data_end,
				  struct icmphdr **ich)
{
	/*
	In c, is pass by value rather than passby reference, so
	when try to send a point, it will create a new pointer and pass
	into func. If func change the value of pointer the old pointer
	will not change, it's why you need use a pointer point to pointer
	*/
	struct icmphdr *ichdr = nh->pos;
	int hdrsize = sizeof(*ichdr);

	if (nh->pos + hdrsize > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*ich = ichdr;
	return ichdr->type;
}

//SEC("xdp")
//int  xdp_pass_func(struct xdp_md *ctx)
//{
//	return xdp_stats_record_action(ctx, XDP_PASS);
//}
//
//SEC("xdp")
//int  xdp_drop_func(struct xdp_md *ctx)
//{
//	return xdp_stats_record_action(ctx, XDP_DROP);
//}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eh;
	struct iphdr *ih;
	struct icmphdr *ich;
	int nh_type, ic_type;
	struct hdr_cursor nh;
	nh.pos = data;

	int action = XDP_PASS;

	// Parse ethernet
	nh_type = parse_ethhdr(&nh, data_end, &eh);
	if (nh_type != bpf_htons(ETH_P_IP)) {
		goto out;
	}

	// Parse IP
	nh_type = parse_iphdr(&nh, data_end, &ih);
	if (nh_type != IPPROTO_ICMP) {
		goto out;
	}

	// Parse ICMP
	ic_type = parse_icmphdr(&nh, data_end, &ich);
	if (ic_type != ICMP_ECHO) {
		goto out;
	}

	//char debug_msg[] = "%s: %d";
	//bpf_trace_printk(debug_msg, sizeof(debug_msg), "type return", ic_type);
	//bpf_trace_printk(debug_msg, sizeof(debug_msg), "type", ich->type);
	//bpf_trace_printk(debug_msg, sizeof(debug_msg), "seq", &ich->un.echo.sequence);
	// Check ICMP seq
	if (bpf_htons(ich->un.echo.sequence) % 2 == 0) {
		action = XDP_DROP;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

// Add GPL license nor can't call bpf_trace_printk
char _license[] SEC("license") = "GPL";
