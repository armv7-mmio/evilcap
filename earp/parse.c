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

		if(!is_valid_ip(target_a) || !is_valid_ip(target_b)) {
			fprintf(stderr, "[!] One or more target IP invalid\n");
			return 1;
		}
	}
	else {
		if(target_a == NULL) {
			fprintf(stderr, "[!] Target IP not specified\n");
			return 1;
		}
	
		if(!is_valid_ip(target_a)) {
			fprintf(stderr, "[!] Target IP invalid\n");
			return 1;
		}
	}

	return 0;
}

bool check_rand_ranges(int rand_min, int rand_max) {
	if(rand_min < 1) {
		fprintf(stderr, "[!] Invalid rand_min value\n");
		return 1;
	}

	if(rand_max < 1) {
		fprintf(stderr, "[!] Invalid rand_max value\n");
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
