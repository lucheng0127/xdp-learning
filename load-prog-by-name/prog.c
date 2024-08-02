//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
Define XDP_ACTION_MAX as arrary length,
use xdp_action as arrary index to recode
pkt and bytes stats
*/
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

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

SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_DROP);
}

// Add GPL license nor can't call bpf_trace_printk
char _license[] SEC("license") = "GPL";
