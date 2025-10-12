#ifndef SNIFF_H
#define SNIFF_H

#include<pcap.h>

void sniff_packets(pcap_if_t*, const char*);

#endif