#pragma once

#include <stdint.h>
#include <stdbool.h>

bool get_local_mac(int fd, const char * interface, uint8_t * mac);
bool is_valid_ip(const char * ip_addr);
