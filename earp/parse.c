#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "parse.h"
#include "netutil.h"

bool check_targets_ip(const char * target_a, const char * target_b, bool is_dual_target) {
	if(is_dual_target) {
		if(target_a == NULL || target_b == NULL) {
			fprintf(stderr, "[!] One or more target IP not specified\n");
			return 1;
		}

		if(check_ip_format(target_a) || check_ip_format(target_b)) {
			fprintf(stderr, "[!] One or more target IP invalid\n");
			return 1;
		}
	}
	else {
		if(target_a == NULL) {
			fprintf(stderr, "[!] Target IP not specified\n");
			return 1;
		}
	
		if(check_ip_format(target_a)) {
			fprintf(stderr, "[!] Target IP invalid\n");
			return 1;
		}
	}

	return 0;
}

bool check_rand_ranges(int rand_min, int rand_max) {
	if(rand_min <= 1) {
		fprintf(stderr, "[!] Invalid rand_min value\n");
		return 1;
	}

	if(rand_max <= 1) {
		fprintf(stderr, "[!] Invalid rand_max value\n");
		return 1;
	}
	
	if(rand_max > 1000) {
		fprintf(stderr, "[!] Rand_max must be less than 1000\n");
		return 1;
	}

	if(rand_min >= rand_max) {
		fprintf(stderr, "[!] Rand_max must be greater than rand_mix\n");
		return 1;	
	}

	return 0;
}

bool check_interface(const char * interface){
	char if_path[256];

	if(interface == 0) {
		fprintf(stderr, "[!] Interface not specified\n");
		return 1;
	}

	snprintf(if_path, sizeof(if_path), "/sys/class/net/%s", interface);

	if(access(if_path, F_OK) == -1) {
		printf("[X] Interface %s does not reachable: %s\n", interface, strerror(errno));
		return 1;
	}

	return 0;
}
