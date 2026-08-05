#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <net/ethernet.h>
#include <linux/capability.h>

#include "arp.h"
#include "util.h"
#include "log.h"

extern volatile sig_atomic_t is_stopping;
volatile sig_atomic_t sig_num;

void setup_signals(void) {
	signal(SIGINT, signal_handler);
	signal(SIGALRM, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGTSTP, signal_handler);
}

void signal_handler(int sig) {
	is_stopping = 1;
	sig_num = sig;
}

void do_cleanup(cleanup_data_t cleanup_data) {
        fprintf(stderr, "\n");
	if(sig_num == SIGALRM)
                fprintf(stderr, "[*] Timer time exceeded\n");
        else
                fprintf(stderr, "[*] Aborted by user\n");

        fprintf(stderr, "[*] Sending gratuitous ARP to re-arping targets\n");
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

        if(fd < 0) {
                fprintf(stderr, "[X] Error: Unable to create socket: %s\n", strerror(errno));
                exit(1);
        }

        char * interface = cleanup_data.interface;
        char * ip_a = cleanup_data.ip_a;
        char * ip_b = cleanup_data.ip_b;
        uint8_t * mac_dst_a = cleanup_data.mac_dst_a;
        uint8_t * mac_dst_b = cleanup_data.mac_dst_b;
        uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        arp_ctx_t arp_ctx_a = {0};
        arp_ctx_t arp_ctx_b = {0};

        if(cleanup_data.ip_b) {
                arp_ctx_a.src_ip = ip_a;
                arp_ctx_a.dst_ip = ip_a;
                arp_ctx_b.src_ip = ip_b;
                arp_ctx_b.dst_ip = ip_b;

                arp_ctx_a.src_mac = mac_dst_a;
                arp_ctx_b.src_mac = mac_dst_b;

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
                int reply_a = 0, reply_b = 0;

                if(cleanup_data.ip_b) {
                        reply_b = arp_reply_from(fd, interface, arp_ctx_b);
			log_reply(arp_ctx_b);
		}

                reply_a = arp_reply_from(fd, interface, arp_ctx_a);
		log_reply(arp_ctx_a);
                
		if(reply_a != 0 || reply_b != 0) {
                        fprintf(stderr, "[x] Error: ARP send falled while cleanup!\n");
                        exit(1);
                }

                usleep(333 * 1000);
        }

        exit(sig_num);
}

int check_capabilities() {
	struct __user_cap_header_struct hdrp = {0};	
	struct __user_cap_data_struct datap = {0};
	
	hdrp.version = _LINUX_CAPABILITY_VERSION_1;
	hdrp.pid = 0;
	
	syscall(SYS_capget, &hdrp, &datap);
	
	if(datap.effective & (1U << CAP_NET_RAW))
		return 1;
	else
		return 0;
}	

