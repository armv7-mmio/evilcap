#pragma once 

typedef struct {
	char * interface;
	char * ip_a;
	char * ip_b;
	uint8_t * mac_dst_a;
	uint8_t * mac_dst_b;
} cleanup_data_t;

void setup_signals(void);

void cleanup_handler(int sig);
