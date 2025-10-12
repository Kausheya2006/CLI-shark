#ifndef UTILS_H
#define UTILS_H

#include "main.h"

const char* decode_ethertype(u_short);
const char* decode_protocol(u_char, u_short );
const char* decode_application_protocol(u_short, u_short);

u_char print_ether_details(const u_char**, u_short, int );

void print_mac_address(const u_char *);
u_short print_ethertype(const u_char *);

u_short print_L4_details(const u_char**, const u_char*, u_short, u_char);

void payload_dump(const u_char*, int);

#endif