#include <string.h> 
#include "storage.h"
#include "main.h"
#include "utils.h"
#include "report_utils.h"

///////// LLM GENERATED CODE /////////
void get_summary(stored_packet_t *stored_packet, int i)
{
    // Buffers to hold formatted parts of the row
    char ts_buf[30];
    char src_mac_buf[18], dest_mac_buf[18];
    char src_ip_buf[16],  dest_ip_buf[16];
    char src_port_buf[10], dest_port_buf[10];

    // Default all to "N/A"
    strcpy(src_ip_buf, "N/A");
    strcpy(dest_ip_buf, "N/A");
    strcpy(src_port_buf, "N/A");
    strcpy(dest_port_buf, "N/A");

    const u_char *packet = stored_packet->data;

    sprintf(ts_buf, "%ld.%06ld", stored_packet->header.ts.tv_sec, (long)stored_packet->header.ts.tv_usec);
    
    sprintf(src_mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    sprintf(dest_mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);

    if (packet[12] == 0x08 && packet[13] == 0x00) // IPv4
    {
        sprintf(src_ip_buf, "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
        sprintf(dest_ip_buf, "%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);
        
        u_char protocol = packet[23];
        const u_char *transport_header = packet + 14 + ((packet[14] & 0x0F) * 4);
        if (protocol == 6 || protocol == 17) // TCP or UDP
        {
            sprintf(src_port_buf, "%d", ntohs(*(u_short *)(transport_header)));
            sprintf(dest_port_buf, "%d", ntohs(*(u_short *)(transport_header + 2)));
        }
    }
    else if (packet[12] == 0x86 && packet[13] == 0xDD) // IPv6
    {
        sprintf(src_ip_buf, "%d.%d.%d.%d...", packet[22], packet[23], packet[24], packet[25]);
        sprintf(dest_ip_buf, "%d.%d.%d.%d...", packet[38], packet[39], packet[40], packet[41]);

        u_char next_header = packet[20];
        const u_char *transport_header = packet + 14 + 40;
        if (next_header == 6 || next_header == 17) // TCP or UDP
        {
            sprintf(src_port_buf, "%d", ntohs(*(u_short *)(transport_header)));
            sprintf(dest_port_buf, "%d", ntohs(*(u_short *)(transport_header + 2)));
        }
    }

    // --- A single, aligned printf call with all columns ---
    printf(" %-4d | %-17s | %-6d | %-17s | %-17s | %-15s | %-15s | %-7s | %-7s \n",
           i + 1,
           ts_buf,
           stored_packet->header.len,
           src_mac_buf,
           dest_mac_buf,
           src_ip_buf,
           dest_ip_buf,
           src_port_buf,
           dest_port_buf);
}

int generate_report(stored_packet_t *stored_packet, int packet_id) {

    const u_char *packet = stored_packet->data;
    const struct pcap_pkthdr *header = &stored_packet->header;
    int total_header_len = 0;

    printf("\n\n%s========================= In-Depth Packet Analysis ========================%s\n", C_TITLE, C_RESET);
    printf("%sPacket ID:%s %d\n", C_LABEL, C_RESET, packet_id);
    printf("%sTimestamp:%s %ld.%06ld\n", C_LABEL, C_RESET, header->ts.tv_sec, (long)header->ts.tv_usec);
    printf("%sCaptured Length:%s %d bytes | %sOriginal Length:%s %d bytes\n", C_LABEL, C_RESET, header->caplen, C_LABEL, C_RESET, header->len);
    printf("%s--------------------------------------------------------------------------%s\n", C_DIM, C_RESET);

    // --- Layer 2: Ethernet Frame ---
    const struct ether_header *eth_header = (struct ether_header *)packet;
    total_header_len = sizeof(struct ether_header);

    printf("\n%s--- Layer 2: Ethernet Frame ---%s\n", C_SECTION, C_RESET);
    printf("  %sDestination MAC:%s %02x:%02x:%02x:%02x:%02x:%02x\n", C_LABEL, C_RESET, eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf("  %sSource MAC:%s      %02x:%02x:%02x:%02x:%02x:%02x\n", C_LABEL, C_RESET, eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    u_short ethertype = ntohs(eth_header->ether_type);
    printf("  %sEtherType:%s       0x%04x (%s)\n", C_LABEL, C_RESET, ethertype, decode_ethertype(ethertype));

    // --- Layer 3 & 4 Dissection ---
    int ip_header_len = 0;
    int transport_protocol = 0;
    int transport_header_len = 0;

    if (ethertype == ETHERTYPE_IP) { // IPv4
        generate_ipv4_report(packet + total_header_len, &ip_header_len, &transport_protocol);
        total_header_len += ip_header_len;

        if (transport_protocol == IPPROTO_TCP) {
            transport_header_len = generate_tcp_report(packet + total_header_len);
        } else if (transport_protocol == IPPROTO_UDP) {
            transport_header_len = generate_udp_report(packet + total_header_len);
        }
        total_header_len += transport_header_len;
    
    } else if (ethertype == ETHERTYPE_IPV6) { // IPv6
        ip_header_len = 40; // Fixed size for base IPv6 header
        generate_ipv6_report(packet + total_header_len, &transport_protocol);
        total_header_len += ip_header_len;
        
        if (transport_protocol == IPPROTO_TCP) {
            transport_header_len = generate_tcp_report(packet + total_header_len);
        } else if (transport_protocol == IPPROTO_UDP) {
            transport_header_len = generate_udp_report(packet + total_header_len);
        }
        total_header_len += transport_header_len;

    } else if (ethertype == ETHERTYPE_ARP) { // ARP
        generate_arp_report(packet + total_header_len);
        total_header_len = header->caplen;
    }

    // --- Payload ---
    printf("\n%s--- Full Packet Data (Headers in Blue) ---%s\n", C_SECTION, C_RESET);
    print_hex_dump(packet, header->caplen, total_header_len);

    return total_header_len;
}

void calculate_session_stats(session_stats_t *stats) {
    memset(stats, 0, sizeof(session_stats_t));
    
    int total_packets = get_stored_packet_count();
    if (total_packets == 0) return;
    
    stats->total_packets = total_packets;
    struct timeval first_ts = {0}, last_ts = {0};
    
    for (int i = 0; i < total_packets; i++) {
        stored_packet_t *stored = get_stored_packet(i);
        if (!stored) continue;
        
        stats->total_bytes += stored->header.len;
        
        if (i == 0) first_ts = stored->header.ts;
        last_ts = stored->header.ts;
        
        const u_char *packet = stored->data;
        if (packet[12] == 0x08 && packet[13] == 0x00) { // IPv4
            uint32_t src_ip, dst_ip;
            memcpy(&src_ip, &packet[26], 4);
            memcpy(&dst_ip, &packet[30], 4);
            
            // Track Source (Bytes Sent)
            int found = 0;
            for (int j = 0; j < stats->top_talker_count; j++) {
                if (stats->top_talkers[j].ip == src_ip) {
                    stats->top_talkers[j].bytes_sent += stored->header.len;
                    found = 1;
                    break;
                }
            }
            if (!found && stats->top_talker_count < 10) {
                stats->top_talkers[stats->top_talker_count].ip = src_ip;
                stats->top_talkers[stats->top_talker_count].bytes_sent = stored->header.len;
                stats->top_talker_count++;
            }
            
            // Track Destination (Bytes Recv)
            found = 0;
            for (int j = 0; j < stats->top_talker_count; j++) {
                if (stats->top_talkers[j].ip == dst_ip) {
                    stats->top_talkers[j].bytes_recv += stored->header.len;
                    found = 1;
                    break;
                }
            }
            if (!found && stats->top_talker_count < 10) {
                stats->top_talkers[stats->top_talker_count].ip = dst_ip;
                stats->top_talkers[stats->top_talker_count].bytes_recv = stored->header.len;
                stats->top_talker_count++;
            }
            
            u_char protocol = packet[23];
            if (protocol == 6) stats->count_tcp++;
            else if (protocol == 17) stats->count_udp++;
            else if (protocol == 1) stats->count_icmp++;
            else stats->count_other++;
            
            if (protocol == 6 || protocol == 17) {
                const u_char *transport = packet + 14 + ((packet[14] & 0x0F) * 4);
                uint16_t sp = ntohs(*(uint16_t*)transport);
                uint16_t dp = ntohs(*(uint16_t*)(transport + 2));
                
                if (sp == 80 || dp == 80) stats->count_http++;
                if (sp == 443 || dp == 443) stats->count_https++;
                if (sp == 53 || dp == 53) stats->count_dns++;
            }
        } else if (packet[12] == 0x08 && packet[13] == 0x06) {
            stats->count_other++; // ARP
        } else {
            stats->count_other++;
        }
    }
    
    double start_sec = first_ts.tv_sec + first_ts.tv_usec / 1000000.0;
    double end_sec = last_ts.tv_sec + last_ts.tv_usec / 1000000.0;
    stats->duration_seconds = end_sec - start_sec;
    if (stats->duration_seconds <= 0.0) stats->duration_seconds = 1.0;
    
    // Sort Top Talkers by Total Volume (Sent + Recv)
    for (int i = 0; i < stats->top_talker_count - 1; i++) {
        for (int j = 0; j < stats->top_talker_count - i - 1; j++) {
            uint64_t v1 = stats->top_talkers[j].bytes_sent + stats->top_talkers[j].bytes_recv;
            uint64_t v2 = stats->top_talkers[j+1].bytes_sent + stats->top_talkers[j+1].bytes_recv;
            if (v1 < v2) {
                ip_stat_t temp = stats->top_talkers[j];
                stats->top_talkers[j] = stats->top_talkers[j+1];
                stats->top_talkers[j+1] = temp;
            }
        }
    }
}