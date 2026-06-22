#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "netutil.h"

bool get_local_mac(int fd, const char * interface, uint8_t * mac) {
	struct ifreq ifrq;

	ifrq.ifr_addr.sa_family = AF_INET;
	strncpy(ifrq.ifr_name, interface, strlen(interface) + 1);
	
	if(ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0) {
		fprintf(stderr, "[X] Error: ioctl falled: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	memcpy(mac, ifrq.ifr_addr.sa_data, 6);
	
	return 0;
}

bool is_valid_ip(const char * ip_addr) {
	uint8_t tmp[4];
	if(inet_pton(AF_INET, ip_addr, &tmp)) {
		return 1;
	}
	else {
		return 0;
	}
}

