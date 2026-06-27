#ifndef MAIN_H
#define MAIN_H

#define MAX_DEVICES 64
#define MAX_PAYLOAD_DUMP 64
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>

#include <signal.h>
#endif