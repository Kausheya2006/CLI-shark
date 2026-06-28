#include "main.h"
#include "storage.h"
#include "utils.h"
#include <ctype.h>
#include "report.h"
#include "llm.h"

void print_hex_dump(const u_char *data, int total_len, int header_len) {
    const int bytes_per_line = 16;
    for (int i = 0; i < total_len; i += bytes_per_line) {
        // Print address offset
        printf("%s  0x%04x:%s ", C_DIM, i, C_RESET);

        // --- Print Hex Values (with color) ---
        for (int j = 0; j < bytes_per_line; j++) {
            if (i + j < total_len) {
                // Set color based on position
                if (i + j < header_len) {
                    printf(C_ACCENT);
                } else {
                    printf(C_RESET);
                }
                printf("%02x ", data[i + j]);
            } else {
                printf("   "); // Pad for alignment
            }
        }
        printf(C_RESET); // Reset color before ASCII part
        printf(" ");

        // --- Print ASCII Representation (with color) ---
        for (int j = 0; j < bytes_per_line; j++) {
            if (i + j < total_len) {
                // Set color based on position
                if (i + j < header_len) {
                    printf(C_ACCENT);
                } else {
                    printf(C_RESET);
                }
                // Print the character
                if (isprint(data[i + j])) {
                    printf("%c", data[i + j]);
                } else {
                    printf(".");
                }
            }
        }
        printf(C_RESET); // Reset color at the end of the line
        printf("\n");
    }
    printf(C_RESET); // Final reset to be safe
}

int generate_tcp_report(const u_char *packet) {
    const struct tcphdr *tcp_header = (const struct tcphdr *)packet;
    int header_length = tcp_header->th_off * 4;

    printf("\n%s--- Layer 4: TCP Segment ---%s\n", C_SECTION, C_RESET);
    printf("  %sSource Port:%s      %u\n", C_LABEL, C_RESET, ntohs(tcp_header->th_sport));
    printf("  %sDestination Port:%s %u\n", C_LABEL, C_RESET, ntohs(tcp_header->th_dport));
    printf("  %sSequence Number:%s  %u\n", C_LABEL, C_RESET, ntohl(tcp_header->th_seq));
    printf("  %sAck Number:%s       %u\n", C_LABEL, C_RESET, ntohl(tcp_header->th_ack));
    printf("  %sHeader Length:%s    %d bytes (Data Offset: %u)\n", C_LABEL, C_RESET, header_length, tcp_header->th_off);
    printf("  %sFlags:%s            0x%02x\n", C_LABEL, C_RESET, tcp_header->th_flags);
    if (tcp_header->th_flags & TH_URG) printf("     %s- Urgent (URG)%s\n", C_VALUE, C_RESET);
    if (tcp_header->th_flags & TH_ACK) printf("     %s- Acknowledgment (ACK)%s\n", C_VALUE, C_RESET);
    if (tcp_header->th_flags & TH_PUSH) printf("     %s- Push (PSH)%s\n", C_VALUE, C_RESET);
    if (tcp_header->th_flags & TH_RST) printf("     %s- Reset (RST)%s\n", C_VALUE, C_RESET);
    if (tcp_header->th_flags & TH_SYN) printf("     %s- Synchronize (SYN)%s\n", C_VALUE, C_RESET);
    if (tcp_header->th_flags & TH_FIN) printf("     %s- Finish (FIN)%s\n", C_VALUE, C_RESET);
    printf("  %sWindow Size:%s      %u\n", C_LABEL, C_RESET, ntohs(tcp_header->th_win));
    printf("  %sChecksum:%s         0x%04x\n", C_LABEL, C_RESET, ntohs(tcp_header->th_sum));

    return header_length;
}


int generate_udp_report(const u_char *packet) {
    const struct udphdr *udp_header = (const struct udphdr *)packet;
    printf("\n%s--- Layer 4: UDP Datagram ---%s\n", C_SECTION, C_RESET);
    printf("  %sSource Port:%s      %u\n", C_LABEL, C_RESET, ntohs(udp_header->uh_sport));
    printf("  %sDestination Port:%s %u\n", C_LABEL, C_RESET, ntohs(udp_header->uh_dport));
    printf("  %sLength:%s           %u\n", C_LABEL, C_RESET, ntohs(udp_header->uh_ulen));
    printf("  %sChecksum:%s         0x%04x\n", C_LABEL, C_RESET, ntohs(udp_header->uh_sum));
    return 8;
}


void generate_ipv4_report(const u_char *packet, int *ip_header_len, int *next_protocol) {
    const struct ip *ip_header = (struct ip *)packet;
    *ip_header_len = ip_header->ip_hl * 4;
    *next_protocol = ip_header->ip_p;

    char src_ip_buf[INET_ADDRSTRLEN];
    char dst_ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_buf, sizeof(src_ip_buf));
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_buf, sizeof(dst_ip_buf));

    printf("\n%s--- Layer 3: IPv4 Datagram ---%s\n", C_SECTION, C_RESET);
    printf("  %sVersion:%s          %d\n", C_LABEL, C_RESET, ip_header->ip_v);
    printf("  %sHeader Length:%s    %d bytes (IHL: %u)\n", C_LABEL, C_RESET, *ip_header_len, ip_header->ip_hl);
    printf("  %sType of Service:%s  0x%02x\n", C_LABEL, C_RESET, ip_header->ip_tos);
    printf("  %sTotal Length:%s     %u\n", C_LABEL, C_RESET, ntohs(ip_header->ip_len));
    printf("  %sIdentification:%s   0x%04x (%u)\n", C_LABEL, C_RESET, ntohs(ip_header->ip_id), ntohs(ip_header->ip_id));
    printf("  %sFlags & Offset:%s   0x%04x\n", C_LABEL, C_RESET, ntohs(ip_header->ip_off));
    if (ntohs(ip_header->ip_off) & IP_DF) printf("     %s- Don't Fragment (DF)%s\n", C_VALUE, C_RESET);
    if (ntohs(ip_header->ip_off) & IP_MF) printf("     %s- More Fragments (MF)%s\n", C_VALUE, C_RESET);
    printf("  %sTime to Live:%s     %d\n", C_LABEL, C_RESET, ip_header->ip_ttl);
    printf("  %sProtocol:%s         %s (%d)\n", C_LABEL, C_RESET, decode_protocol(*next_protocol, ETHERTYPE_IP), *next_protocol);
    printf("  %sHeader Checksum:%s  0x%04x\n", C_LABEL, C_RESET, ntohs(ip_header->ip_sum));
    printf("  %sSource IP:%s        %s\n", C_LABEL, C_RESET, src_ip_buf);
    printf("  %sDestination IP:%s   %s\n", C_LABEL, C_RESET, dst_ip_buf);
}


void generate_arp_report(const u_char *packet) {
    const struct arphdr *arp_header = (const struct arphdr *)(packet);
    // The ARP packet payload contains the MAC and IP addresses
    const u_char *arp_payload = (u_char *)(arp_header + 1);

    printf("\n%s--- Layer 3: ARP Message ---%s\n", C_SECTION, C_RESET);
    printf("  %sHardware Type:%s    %u (%s)\n", C_LABEL, C_RESET, ntohs(arp_header->ar_hrd), (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER) ? "Ethernet" : "Unknown");
    printf("  %sProtocol Type:%s    0x%04x (%s)\n", C_LABEL, C_RESET, ntohs(arp_header->ar_pro), (ntohs(arp_header->ar_pro) == ETHERTYPE_IP) ? "IPv4" : "Unknown");
    printf("  %sHardware Size:%s    %u bytes\n", C_LABEL, C_RESET, arp_header->ar_hln);
    printf("  %sProtocol Size:%s    %u bytes\n", C_LABEL, C_RESET, arp_header->ar_pln);
    printf("  %sOpcode:%s           %u (%s)\n", C_LABEL, C_RESET, ntohs(arp_header->ar_op), (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply");

    // Extracting addresses from the ARP payload
    printf("  %sSender MAC:%s       %02x:%02x:%02x:%02x:%02x:%02x\n", C_LABEL, C_RESET, arp_payload[0], arp_payload[1], arp_payload[2], arp_payload[3], arp_payload[4], arp_payload[5]);
    printf("  %sSender IP:%s        %d.%d.%d.%d\n", C_LABEL, C_RESET, arp_payload[6], arp_payload[7], arp_payload[8], arp_payload[9]);
    printf("  %sTarget MAC:%s       %02x:%02x:%02x:%02x:%02x:%02x\n", C_LABEL, C_RESET, arp_payload[10], arp_payload[11], arp_payload[12], arp_payload[13], arp_payload[14], arp_payload[15]);
    printf("  %sTarget IP:%s        %d.%d.%d.%d\n", C_LABEL, C_RESET, arp_payload[16], arp_payload[17], arp_payload[18], arp_payload[19]);
}



void generate_ipv6_report(const u_char *packet, int *next_protocol) {
    const struct ip6_hdr *ip6_header = (struct ip6_hdr *)packet;
    *next_protocol = ip6_header->ip6_nxt;

    char src_ip_buf[INET6_ADDRSTRLEN];
    char dst_ip_buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_buf, sizeof(src_ip_buf));
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_buf, sizeof(dst_ip_buf));

    printf("\n%s--- Layer 3: IPv6 Datagram ---%s\n", C_SECTION, C_RESET);
    printf("  %sVersion:%s          %u\n", C_LABEL, C_RESET, (ip6_header->ip6_vfc >> 4) & 0x0F);
    printf("  %sTraffic Class:%s    0x%02x\n", C_LABEL, C_RESET, ((ip6_header->ip6_vfc & 0x0F) << 4) | ((ip6_header->ip6_flow & 0xF00000) >> 20));
    printf("  %sFlow Label:%s       0x%05x\n", C_LABEL, C_RESET, ntohl(ip6_header->ip6_flow) & 0x0FFFFF);
    printf("  %sPayload Length:%s   %u\n", C_LABEL, C_RESET, ntohs(ip6_header->ip6_plen));
    printf("  %sNext Header:%s      %s (%u)\n", C_LABEL, C_RESET, decode_protocol(*next_protocol, ETHERTYPE_IPV6), *next_protocol);
    printf("  %sHop Limit:%s        %u\n", C_LABEL, C_RESET, ip6_header->ip6_hlim);
    printf("  %sSource IP:%s        %s\n", C_LABEL, C_RESET, src_ip_buf);
    printf("  %sDestination IP:%s   %s\n", C_LABEL, C_RESET, dst_ip_buf);
}

void askLLM(stored_packet_t *packet, int packet_id, int total_header_len){

    FILE *tmp = tmpfile();
    if (!tmp) return;

    int og_stdout = dup(fileno(stdout));

    // redirect stdout to tmp file
    dup2(fileno(tmp), fileno(stdout));
    generate_report(packet, packet_id);
    fflush(stdout);
    dup2(og_stdout, fileno(stdout));
    close(og_stdout);

    fseek(tmp, 0, SEEK_SET); // beginning

    char line[256];
    char header_content[4096] = {0};

    // everything before full packet data
    while (fgets(line, sizeof(line), tmp))
    {
        if (strstr(line, "========================= In-Depth Packet Analysis ========================"))
            continue;

        if (strstr(line, "--- Full Packet Data (Headers in Blue) ---"))
            break;
        
        strncat(header_content, line, sizeof(header_content) - strlen(header_content) - 1);
    }
    fclose(tmp);

    int caplen = packet->header.caplen;
    
    char clean_header[4096] = {0};
    strip_ansi_codes(header_content, clean_header, sizeof(clean_header));

    char *llmprompt = calloc(1, strlen(clean_header) + caplen + 512);
    if (!llmprompt)     return;

    snprintf(llmprompt, strlen(clean_header) + 512, 
    "You are an expert network analyst. Look at these headers and the extracted ASCII payload. What is this traffic doing? Keep it under 3 sentences.\n\n"
    "HEADERS:\n%s\n"
    "ASCII PAYLOAD:\n", clean_header);


    // concatenate body
    int curr_idx = strlen(llmprompt);
    const u_char *packet_data = packet->data;

    for (int i=total_header_len; i < caplen; i++)
    {
        if (isprint(packet_data[i]))   
            llmprompt[curr_idx++] = packet_data[i];
        else
            llmprompt[curr_idx++] = '.';
    }
    llmprompt[curr_idx] = '\0';

    //printf("\n\n Prompt : %s\n\n", llmprompt);

    send_to_llm_api(llmprompt);
    //printf("%s", llmprompt);
    free(llmprompt);
}