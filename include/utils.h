#ifndef UTILS_H
#define UTILS_H

#include "main.h"

#define C_RESET   "\x1b[0m"
#define C_TITLE   "\x1b[1;36m"
#define C_SECTION "\x1b[1;34m"
#define C_LABEL   "\x1b[1;33m"
#define C_VALUE   "\x1b[0;37m"
#define C_DIM     "\x1b[2m"
#define C_OK      "\x1b[32m"
#define C_WARN    "\x1b[33m"
#define C_ERR     "\x1b[31m"
#define C_ACCENT  "\x1b[35m"

const char* decode_ethertype(u_short);
const char* decode_protocol(u_char, u_short );
const char* decode_application_protocol(u_short, u_short);

u_char print_ether_details(const u_char**, u_short, int );

void print_mac_address(const u_char *);
u_short print_ethertype(const u_char *);

u_short print_L4_details(const u_char**, const u_char*, u_short, u_char);

void payload_dump(const u_char*, int);

size_t strip_ansi_codes(const char *input, char *output, size_t output_size);

#endif