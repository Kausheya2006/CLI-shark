#ifndef STORAGE_H
#define STORAGE_H

#include <pcap.h>

#define MAX_PACKETS 10000

typedef struct {
    struct pcap_pkthdr header; // meta-data (timestamp, caplen, len)
    u_char *data;              // individual packets
} stored_packet_t;


void clear_last_session();

void store_packet(const struct pcap_pkthdr *, const u_char *);

void set_session_linktype(int);

int export_session_to_pcap(const char *);

int load_session_from_pcap(const char *);

int get_stored_packet_count();

stored_packet_t* get_stored_packet(int); 

#endif