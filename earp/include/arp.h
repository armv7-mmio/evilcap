#pragma once

#include <stdint.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#define ARP_RESOLVE_TIMEOUT 1000

typedef struct {
	char * src_ip;
	char * dst_ip;
	uint8_t * src_mac;
	uint8_t * dst_mac;
} arp_ctx_t;

typedef struct __attribute__((packed)) {
	struct ethhdr ethh;
	struct ether_arp eth_arp;
} arp_frame_t;

int arp_resolve(int fd, const char * interface, arp_ctx_t arp_ctx);

int arp_reply(int fd, const char * interface, arp_ctx_t arp_ctx);

int arp_reply_from(int fd, const char * interface, arp_ctx_t arp_ctx);

