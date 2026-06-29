#include <stdio.h>
#include <netinet/ether.h>
#include "arp.h"
#include "log.h"

void print_help(void) {
	fprintf(stderr, "%s", help_msg);
}

void log_reply(arp_ctx_t arp_ctx) {
	char src_mac[6], dst_mac[6];

	ether_ntoa_r((struct ether_addr * )&arp_ctx.src_mac, src_mac);
	ether_ntoa_r((struct ether_addr * )&arp_ctx.dst_mac, dst_mac);
	
	fprintf(stderr, "ARP reply, sha: %s, tha: %s, spa: %s, tpa: %s\n",
		src_mac,
		dst_mac,
		arp_ctx.src_ip,
		arp_ctx.dst_ip);
}
