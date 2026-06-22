#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "arp.h"

static uint64_t get_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool arp_resolve(int fd, const char * interface, const char * src_ip, const char * dst_ip, uint8_t * dst_mac, const uint8_t * src_mac) {
	struct sockaddr_ll sll = {0};
	struct ether_arp arpf = {0};
	struct ether_arp arpf_recv = {0};
	
	uint64_t end_time = get_time_ms() + ARP_RESOLVE_TIMEOUT;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = 6;
	
	memset(sll.sll_addr, 0xFF, 6);

	memcpy(arpf.arp_sha, src_mac, 6);
	if(src_ip)
		inet_pton(AF_INET, src_ip, arpf.arp_spa);			
	inet_pton(AF_INET, dst_ip, arpf.arp_tpa);
	arpf.arp_hrd = htons(ARPHRD_ETHER);
	arpf.arp_pro = htons(ETH_P_IP);
	arpf.arp_hln = 6;
	arpf.arp_pln = 4;
	arpf.arp_op = htons(ARPOP_REQUEST);

	if(sendto(fd, &arpf, sizeof(arpf), 0,(const struct sockaddr *)&sll, sizeof(arpf)) <= 0){
		fprintf(stderr, "[X] Error: unable to send: %s\n", strerror(errno));
		return 1;
	}

	while(get_time_ms() < end_time) {
		ssize_t n = recvfrom(fd, &arpf_recv, sizeof(arpf_recv), 0, 0, 0);
		if (n < 0) {
			fprintf(stderr, "[X] Error: Falled to recivie frame:\n", strerror(errno));
			return 1;
		}

		if(htons(arpf_recv.arp_op) == ARPOP_REPLY) {
			if(!memcmp(arpf_recv.arp_tha, src_mac, 6) && !memcmp(arpf_recv.arp_spa, arpf.arp_tpa, 4)){
				memcpy(dst_mac, arpf_recv.arp_sha, 6);
				return 0;
			}
		}
	}
	return 1;
}

bool arp_reply(int fd, const char * interface, const char * src_ip, const char * target_ip, const uint8_t * src_mac, const uint8_t * dst_mac) { 
	struct sockaddr_ll sll;
	struct ether_arp arpf;
	
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, dst_mac, 6);	

	memcpy(arpf.arp_sha, src_mac, 6);
	memcpy(arpf.arp_tha, dst_mac, 6);
	inet_pton(AF_INET, src_ip, arpf.arp_spa);			
	inet_pton(AF_INET, target_ip, arpf.arp_tpa);
	arpf.arp_hrd = htons(ARPHRD_ETHER);
	arpf.arp_pro = htons(ETH_P_IP);
	arpf.arp_hln = 6;
	arpf.arp_pln = 4;
	arpf.arp_op = htons(ARPOP_REPLY);

	if(sendto(fd, &arpf, sizeof(arpf), 0,(const struct sockaddr *)&sll, sizeof(arpf)) <= 0){
		fprintf(stderr, "[X] Error: unable to send: %s\n", strerror(errno));
		return 1;
	}
	else {
		return 0;
	}
}	
