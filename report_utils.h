#ifndef REPORT_UTILS_H
#define REPORT_UTILS_H

#include "main.h"
#include "storage.h"

const char* decode_protocol(u_char , u_short );


void print_hex_dump(const u_char *, int, int );


int generate_tcp_report(const u_char *);


int generate_udp_report(const u_char *);


void generate_ipv4_report(const u_char *, int *, int *);


void generate_arp_report(const u_char *);


void generate_ipv6_report(const u_char *, int *);


#endif 