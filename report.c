#include <string.h> 
#include "storage.h"
#include "main.h"
#include "utils.h"


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
///////// END OF LLM GENERATED CODE /////////


void generate_report(stored_packet_t *stored_packet, int packet_id) {
    const u_char *packet = stored_packet->data;
    const struct pcap_pkthdr *header = &stored_packet->header;
    int total_header_len = 0;

    printf("\n\n========================= In-Depth Packet Analysis ========================\n");
    printf("Packet ID: %d\n", packet_id);
    printf("Timestamp: %ld.%06ld\n", header->ts.tv_sec, (long)header->ts.tv_usec);
    printf("Captured Length: %d bytes | Original Length: %d bytes\n", header->caplen, header->len);
    printf("--------------------------------------------------------------------------\n");

    // --- Layer 2: Ethernet Frame ---
    const struct ether_header *eth_header = (struct ether_header *)packet;
    total_header_len = sizeof(struct ether_header);

    printf("\n--- Layer 2: Ethernet Frame ---\n");
    printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf("  Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    u_short ethertype = ntohs(eth_header->ether_type);
    printf("  EtherType:       0x%04x (%s)\n", ethertype, decode_ethertype(ethertype));

    // --- Layer 3 & 4 Dissection ---
    int ip_header_len = 0;
    int transport_protocol = 0;
    int transport_header_len = 0;

    if (ethertype == ETHERTYPE_IP) { // IPv4
        
        total_header_len += ip_header_len;

        if (transport_protocol == IPPROTO_TCP) {
            transport_header_len = 0;
        } else if (transport_protocol == IPPROTO_UDP) {
            transport_header_len = 0;
        }
        total_header_len += transport_header_len;
    
    } else if (ethertype == ETHERTYPE_IPV6) { // IPv6
        ip_header_len = 40; // Fixed size for base IPv6 header
        
        total_header_len += ip_header_len;
        
        if (transport_protocol == IPPROTO_TCP) {
            transport_header_len = 0;
        } else if (transport_protocol == IPPROTO_UDP) {
            transport_header_len = 0;
        }
        total_header_len += transport_header_len;

    } else if (ethertype == ETHERTYPE_ARP) { // ARP
        
        total_header_len = header->caplen;
    }

    // --- Payload ---
    printf("\n--- Full Packet Data (Headers in Blue) ---\n");
    // print_hex_dump(packet, header->caplen, total_header_len);
    
    printf("\n============================= End of Analysis =============================\n\n");
    
}