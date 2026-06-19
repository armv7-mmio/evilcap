#pragma once

#include <stdint.h>
#include <stdbool.h>

#define ARP_REPLY_TIMEOUT 5000

bool arp_resolve(int fd, const char * interface, const char * src_ip, const char * dst_ip, uint8_t * dst_mac, const uint8_t * src_mac);

bool arp_reply(int fd, const char * interface, const char * src_ip, const char * target_ip, const uint8_t * src_mac, const uint8_t * dst_mac);

bool get_local_mac(int fd, const char * interface, uint8_t * mac);
