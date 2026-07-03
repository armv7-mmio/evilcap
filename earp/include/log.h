#pragma once
#include "arp.h"

static const char * help_msg = R"abc(
EvilARP v1.0
Usage: earp [options]
Options: 
	-h, --help              Show this message.
	-t, --target            Specify the target IP address.
	-a, --target-a          Target IP A (only in dual target mode).
	-b, --target-b          Target IP B (only in dual target mode).
	-d, --dual-target       Enable dual target mode (MITM).
	-g, --gratuitous        Send gratuitous ARP packets.
	-i, --interface         Specify the network interface (e.g., eth0, wlan0).
	-m, --rand-min          Minimum delay between packets (ms).
	-M, --rand-max          Maximum delay between packets (ms).
	-s, --storm             ARP storm mode (send packets without delay).
	-T, --timer             Set timeout in seconds. Program will exit, when time expires.
Notes:  For dual-target mode, use -d with both -a and -b flags.
        ARP storm mode may crash the network!
Warning: This tool is for authorized network testing only! Use at your own risk.
)abc";

void print_help(void);
void log_reply(const arp_ctx_t arp_ctx);
