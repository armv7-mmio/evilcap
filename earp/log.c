#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include "arp.h"
#include "log.h"

void print_help(void) {
	fprintf(stderr, "%s", help_msg);
}

void log_gratuitous(const uint8_t * mac_addr, const char * ip_addr) {
	char mac_str[32];
	ether_ntoa_r((struct ether_addr *)mac_addr, mac_str);
	fprintf(stderr, "[*] Gratuitous ARP: sha:%s; sha/tha:%s\n", mac_str, ip_addr);
}

void log_reply(const arp_ctx_t arp_ctx) {
	if(!strcmp(arp_ctx.src_ip, arp_ctx.dst_ip)) {
		log_gratuitous(arp_ctx.src_mac, arp_ctx.src_ip);
		return;
	}
	
	char src_mac_str[64], dst_mac_str[64];

	ether_ntoa_r((struct ether_addr * )arp_ctx.src_mac, src_mac_str);
	ether_ntoa_r((struct ether_addr * )arp_ctx.dst_mac, dst_mac_str);
	
	fprintf(stderr, "[*] ARP reply: sha: %s; tha: %s; spa: %s; tpa: %s\n",
		src_mac_str,
		dst_mac_str,
		arp_ctx.src_ip,
		arp_ctx.dst_ip);
}
