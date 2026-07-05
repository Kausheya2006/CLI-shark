#ifndef REPORT_H
#define REPORT_H
#include "storage.h"

#include <netinet/in.h>
#include <stdint.h>

typedef struct {
    uint32_t ip;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
} ip_stat_t;

typedef struct {
    int total_packets;
    uint64_t total_bytes;
    double duration_seconds;
    
    // Protocols
    int count_tcp;
    int count_udp;
    int count_icmp;
    int count_http;
    int count_https;
    int count_dns;
    int count_other;
    
    // Top Talkers (Top 10)
    ip_stat_t top_talkers[10];
    int top_talker_count;
} session_stats_t;

void get_summary(stored_packet_t *, int);
int generate_report(stored_packet_t *, int);
void calculate_session_stats(session_stats_t *stats);

#endif