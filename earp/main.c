#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int arp_reply(int fd, const char * interface, const char * src_ip, const char * target_ip) { 
	struct sockaddr_ll sll = {0};
	struct ether_arp arpf = {0};
	struct ifreq ifrq = {0};
	
	ifrq.ifr_addr.sa_family = AF_INET;
	strncpy(ifrq.ifr_name, interface, IFNAMSIZ - 1);

	if(ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0) {
		fprintf(stderr, "Error: unable to call ioctl: %s", strerror(errno));
		close(fd);
		return -1;
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

	if(sendto(fd, &arpf, sizeof(arpf), 0,(const struct sockaddr *)&sll, sizeof(arpf)) <= 0)
		fprintf(stderr, "Error: unable to create socket: %s", strerror(errno));
}
int main (int argc, char * argv) {
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));	
	arp_reply(fd, "eth0", "10.0.0.1", "10.255.255.255"); // test of arp frames injection
	close(fd);
	return 0;
}	
