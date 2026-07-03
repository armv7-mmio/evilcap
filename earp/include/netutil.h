#pragma once

#include <stdint.h>
#include <stdbool.h>

bool get_local_mac(int fd, const char * interface, uint8_t * mac);
bool check_ip_format(const char * ip_addr);
bool is_reserved_ip(const char * ip_addr);
