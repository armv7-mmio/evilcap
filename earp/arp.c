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

int arp_resolve(int fd, const char * interface, arp_ctx_t arp_ctx) {
	struct sockaddr_ll sll = {0};
	struct ether_arp arpf = {0};
	struct ether_arp arpf_recv = {0};
	
	uint64_t end_time = get_time_ms() + ARP_RESOLVE_TIMEOUT;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = 6;
	
	memset(sll.sll_addr, 0xFF, 6);

	memcpy(arpf.arp_sha, arp_ctx.src_mac, 6);
	if(arp_ctx.src_ip)
		inet_pton(AF_INET, arp_ctx.src_ip, arpf.arp_spa);			
	inet_pton(AF_INET, arp_ctx.dst_ip, arpf.arp_tpa);
	arpf.arp_hrd = htons(ARPHRD_ETHER);
	arpf.arp_pro = htons(ETH_P_IP);
	arpf.arp_hln = 6;
	arpf.arp_pln = 4;
	arpf.arp_op = htons(ARPOP_REQUEST);
	
	struct sockaddr * saddr = (struct sockaddr *)&sll;

	ssize_t tx_n = sendto(fd, &arpf, sizeof(arpf), 0, saddr, sizeof(sll)); 

	if(tx_n < 0){
		int err = errno;
		fprintf(stderr, "[X] Error: unable to send: %s\n", strerror(errno));
		return err;
	}
	
	while(get_time_ms() < end_time) {
		ssize_t n = recv(fd, &arpf_recv, sizeof(arpf_recv), MSG_DONTWAIT);
		
		if (n < 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			
			int err = errno;
			fprintf(stderr, "[X] Error: Falled to recivie frame:\n", strerror(errno));
			return err;
		}

		if(htons(arpf_recv.arp_op) != ARPOP_REPLY)
			continue;

		if(memcmp(arpf_recv.arp_tha, arp_ctx.src_mac, 6) != 0)
			continue;

		if(memcmp(arpf_recv.arp_spa, arpf.arp_tpa, 4) != 0)
			continue;
		
		memcpy(arp_ctx.dst_mac, arpf_recv.arp_sha, 6);
		return 0;
	}

	return -1;
}

int arp_reply(int fd, const char * interface, arp_ctx_t arp_ctx) { 
	struct sockaddr_ll sll;
	struct ether_arp arpf;
	
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, arp_ctx.dst_mac, 6);	

	memcpy(arpf.arp_sha, arp_ctx.src_mac, 6);
	memcpy(arpf.arp_tha, arp_ctx.dst_mac, 6);
	inet_pton(AF_INET, arp_ctx.src_ip, arpf.arp_spa);			
	inet_pton(AF_INET, arp_ctx.dst_ip, arpf.arp_tpa);
	arpf.arp_hrd = htons(ARPHRD_ETHER);
	arpf.arp_pro = htons(ETH_P_IP);
	arpf.arp_hln = 6;
	arpf.arp_pln = 4;
	arpf.arp_op = htons(ARPOP_REPLY);
	
	struct sockaddr * saddr = (struct sockaddr *)&sll;
	ssize_t tx_n = sendto(fd, &arpf, sizeof(arpf), 0, saddr, sizeof(sll)); 

	if(tx_n <= 0){
		int err = errno;
		fprintf(stderr, "[X] Error: unable to send: %s\n", strerror(errno));
		return err;
	}
	
	return 0;
}
/*
int arp_reply_from(int fd, const char * interface, arp_ctx_t arp_ctx) { 
	struct sockaddr_ll sll;
	struct ether_arp arpf;
	
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, arp_ctx.dst_mac, 6);	

	memcpy(arpf.arp_sha, arp_ctx.src_mac, 6);
	memcpy(arpf.arp_tha, arp_ctx.dst_mac, 6);
	inet_pton(AF_INET, arp_ctx.src_ip, arpf.arp_spa);			
	inet_pton(AF_INET, arp_ctx.dst_ip, arpf.arp_tpa);
	arpf.arp_hrd = htons(ARPHRD_ETHER);
	arpf.arp_pro = htons(ETH_P_IP);
	arpf.arp_hln = 6;
	arpf.arp_pln = 4;
	arpf.arp_op = htons(ARPOP_REPLY);
	
	struct sockaddr * saddr = (struct sockaddr *)&sll;
	ssize_t tx_n = sendto(fd, &arpf, sizeof(arpf), 0, saddr, sizeof(sll)); 

	if(tx_n <= 0){
		int err = errno;
		fprintf(stderr, "[X] Error: unable to send: %s\n", strerror(errno));
		return err;
	}
	
	return 0;
}
*/
