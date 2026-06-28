#include<strings.h>
#include "utils.h"
/*
This contains all print utilities (like printing mac add, ip add, ...)
*/


const char* decode_ethertype(u_short ethertype)
{
    switch (ethertype)
    {
        case 0x0800: 
            return "IPv4";
        case 0x86DD:
            return "IPv6";
        case 0x0806: 
            return "ARP";
        default:     
            return "Unknown";
    }
}

const char* decode_protocol(u_char protocol, u_short ethertype)
{

    if (ethertype == 0x0800)  // IPv4
    {
        switch (protocol)
        {
            case 1:  
                return "ICMP";
            case 6:  
                return "TCP";
            case 17: 
                return "UDP";
            default: 
                return "Unknown";
        }
    }
    else if (ethertype == 0x86DD)  // IPv6
    {
        switch (protocol)
        {
            case 58: 
                return "ICMPv6";
            case 6:  
                return "TCP";
            case 17: 
                return "UDP";
            default: 
                return "Unknown";
        }
    }
    return "N/A";
   
}

const char* decode_application_protocol(u_short src_port, u_short dest_port)
{
    if (src_port == 80 || dest_port == 80)
        return "HTTP";
    else if (src_port == 443 || dest_port == 443)
        return "HTTPS";
    else if (src_port == 53 || dest_port == 53)
        return "DNS";
    else
        return "Unknown";
}

u_char print_ether_details(const u_char **packet_ptr, u_short ethertype, int packet_id)
{

    if (ethertype == 0x0800)  // IPv4
    {
        /* IP HEADER STRUCTURE : 
        { version + IHL (1 byte), 
         type of service (1 byte), 
         total length (2 bytes),
         identification (2 bytes),
         flags + fragment offset (2 bytes),
         time to live (1 byte), 
         protocol (1 byte), 
         header checksum (2 bytes),
         source address (4 bytes), 
         destination address (4 bytes) }
        */
        const u_char *ip_header = *packet_ptr;  // Starting at packet[14] (after ethernet header)
        *packet_ptr += (ip_header[0] & 0x0F) * 4;  // Move current position by IHL bytes (Internet Header Length) (first 4 bits of first byte)
        

        printf("%sSource IP%s : %d.%d.%d.%d  | ", C_LABEL, C_RESET, ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        printf("%sDestination IP%s : %d.%d.%d.%d  | ", C_LABEL, C_RESET, ip_header[16], ip_header[17], ip_header[18], ip_header[19]);


        u_char protocol = ip_header[9];

        const char* decoded_type = decode_protocol(protocol, ethertype);
        printf("%sProtocol%s : %s (%d)  | ", C_LABEL, C_RESET, decoded_type, protocol); // TCP / UDP / ICMP / ...


         printf("%sTTL%s : %d  | %sPacket ID%s : %d  | %sTotal Length%s : %d | %sHeader Length%s : %d  |\n",
             C_LABEL, C_RESET, ip_header[8],
             C_LABEL, C_RESET, packet_id,
             C_LABEL, C_RESET, ntohs(*(u_short*)(ip_header + 2)),
             C_LABEL, C_RESET, (ip_header[0] & 0x0F) * 4);
        // ntoh : network to host byte order conversion (big-endian to little-endian)
        // (ip_header[0] & 0x0F) * 4 : masking first 4 bits to get IHL (Internet Header Length) and multiplying by 4 to get length in bytes
        printf("%sFlags%s : ", C_LABEL, C_RESET);
        u_short flags_fragment = ntohs(*(u_short*)(ip_header + 6));
        u_short flags = (flags_fragment >> 13) & 0x07;

        if (flags & 0x04)
            printf("Reserved (0x04) ");
        if (flags & 0x02)
            printf("Don't Fragment (0x02) ");
        if (flags & 0x01)
            printf("More Fragments (0x01) ");
        if (flags == 0)
            printf("None (0x00) ");

        printf("  | %sFragment Offset%s : %d\n", C_LABEL, C_RESET, flags_fragment & 0x1FFF);
        // masking first 3 bits to get flags and last 13 bits to get fragment offset    

        return protocol;

    }
    else if (ethertype == 0x86DD)  // IPv6
    {
        /* IPv6 HEADER STRUCTURE : 
        { version + traffic class + flow label (4 bytes), 
         payload length (2 bytes),
         next header (1 byte),
         hop limit (1 byte),
         source address (16 bytes),
         destination address (16 bytes) }
        */
        const u_char *ip_header = *packet_ptr;  // Starting at packet[14] (after ethernet header)

        *packet_ptr += 40;  // IPv6 header fixed size = 40

        printf("%sSource IP%s : ", C_LABEL, C_RESET);
        for (int i=0; i<16; i++)
        {
            printf("%02X", ip_header[8 + i]);
            if (i % 2 != 0 && i != 15)
                printf(":");
        }
        printf("  | %sDestination IP%s : ", C_LABEL, C_RESET);
        for (int i=0; i<16; i++)
        {
            printf("%02X", ip_header[24 + i]);
            if (i % 2 != 0 && i != 15)
                printf(":");
        }
        printf("  | ");

        u_char next_header = ip_header[6];
        const char* decoded_type = decode_protocol(next_header, ethertype);
        printf("%sNext Header%s : %s (%d)  | ", C_LABEL, C_RESET, decoded_type, next_header);

         printf("%sHop Limit%s : %d  | %sTraffic Class%s : %d  | %sFlow Label%s : %d  | %sPayload Length%s : %d |\n",
             C_LABEL, C_RESET, ip_header[7],
             C_LABEL, C_RESET, ((ip_header[0] & 0x0F) << 4) | (ip_header[1] >> 4),
             C_LABEL, C_RESET, ((ip_header[1] & 0x0F) << 16) | (ip_header[2] << 8) | ip_header[3],
             C_LABEL, C_RESET, ntohs(*(u_short*)(ip_header + 4)));

        return next_header;
    }
    else if (ethertype == 0x0806)  // ARP
    {
        /* ARP HEADER STRUCTURE : 
        { hardware type (2 bytes), 
         protocol type (2 bytes),
         hardware size (1 byte),
         protocol size (1 byte),
         opcode (2 bytes),
         sender MAC address (6 bytes),
         sender IP address (4 bytes),
         target MAC address (6 bytes),
         target IP address (4 bytes) }
        */
        const u_char *arp_header = *packet_ptr;  // Starting at packet[14] (after ethernet header)

        u_short opcode = ntohs(*(u_short*)(arp_header + 6));
        printf("%sOperation%s : ", C_LABEL, C_RESET);
        if (opcode == 1)
            printf("Request (1)  | ");
        else if (opcode == 2)
            printf("Reply (2)  | ");
        else
            printf("Unknown (%d)  | ", opcode);

        printf("%sSender MAC%s : ", C_LABEL, C_RESET);
        for (int i=0; i<6; i++)
        {
            printf("%02X", arp_header[8 + i]);
            printf((i < 5) ? ":" : " |  ");
        }
        printf("%sSender IP%s : %d.%d.%d.%d  | ", C_LABEL, C_RESET, arp_header[14], arp_header[15], arp_header[16], arp_header[17]);

        printf("%sTarget MAC%s : ", C_LABEL, C_RESET);
        for (int i=0; i<6; i++)
        {
            printf("%02X", arp_header[18 + i]);
            printf((i < 5) ? ":" : " |  ");
        }
        printf("%sTarget IP%s : %d.%d.%d.%d |\n", C_LABEL, C_RESET, arp_header[24], arp_header[25], arp_header[26], arp_header[27]);

         printf("%sHardware Type%s : %d  | %sProtocol Type%s : 0x%04X  | %sHardware Size%s : %d  | %sProtocol Size%s : %d |\n",
             C_LABEL, C_RESET, ntohs(*(u_short*)(arp_header)),
             C_LABEL, C_RESET, ntohs(*(u_short*)(arp_header + 2)),
             C_LABEL, C_RESET, arp_header[4],
             C_LABEL, C_RESET, arp_header[5]);

    }
    else
    {
        printf("%sNo further details for this Ethertype.%s\n", C_DIM, C_RESET);
    }

   return 0;

}

void print_mac_address(const u_char *mac)  // 0-5 byte : source mac, 6-11 byte : dest mac
{
    printf("%sSource MAC%s : ", C_LABEL, C_RESET);
    for (int i=0; i<6; i++)
    {
        printf("%02X", mac[i]);
        printf((i < 5) ? ":" : " |  ");
    }
    printf("%sDestination MAC%s : ", C_LABEL, C_RESET);
    for (int i=6; i<12; i++)
    {
        printf("%02X", mac[i]);
        printf((i < 11) ? ":" : " |  ");
    }
    printf("\n");
}

u_short print_ethertype(const u_char *packet)  // concatenate 12,13-th byte : ethertype
{
    u_short ethertype = (packet[12] << 8 | packet[13]);  // combining two bytes to form ethertype (big-endian)
    
    const char* decoded_type = decode_ethertype(ethertype);
    printf("%sEthertype%s : %s (0x%04X)  |\n", C_LABEL, C_RESET, decoded_type, ethertype);
    return ethertype;
}

u_short print_L4_details(const u_char **packet_ptr, const u_char *packet, u_short ethertype, u_char protocol)
{
    
    const u_char *transport_header = *packet_ptr;  // Starting at the end of IP header

    u_short return_protocol_value = 0;  // Default to 0 for unidentified ports (0 is reserved/invalid)

    int transport_header_length = 0;
    
    if (protocol == 6)  // TCP
    {
        /* TCP HEADER STRUCTURE : 
        { source port (2 bytes), 
            destination port (2 bytes),
            sequence number (4 bytes),
            acknowledgment number (4 bytes),
            data offset + reserved + flags (2 bytes),
            window size (2 bytes),
            checksum (2 bytes),
            urgent pointer (2 bytes) }
        */

        u_short src_port = ntohs(*(u_short*)(transport_header));
        u_short dst_port = ntohs(*(u_short*)(transport_header + 2));
        
        printf("%sSource Port%s : %d  | ", C_LABEL, C_RESET, src_port);
        printf("%sDestination Port%s : %d  | ", C_LABEL, C_RESET, dst_port);

        if (src_port == 80 || dst_port == 80)
            return_protocol_value = 80;
        else if (src_port == 443 || dst_port == 443)
            return_protocol_value = 443;
        else if (src_port == 53 || dst_port == 53)
            return_protocol_value = 53;
        else
            return_protocol_value = (dst_port >= 1024) ? dst_port : src_port;  // Return the higher port (likely ephemeral)

        printf("%sApplication Protocol%s : %s  | ", C_LABEL, C_RESET, decode_application_protocol(src_port, dst_port));

        printf("%sSequence Number%s : %u  | ", C_LABEL, C_RESET, ntohl(*(u_int*)(transport_header + 4)));
        printf("%sAcknowledgment Number%s : %u  | ", C_LABEL, C_RESET, ntohl(*(u_int*)(transport_header + 8)));

        u_short data_offset_reserved_flags = ntohs(*(u_short*)(transport_header + 12));
        u_char data_offset = (data_offset_reserved_flags >> 12) & 0x0F;

        transport_header_length = data_offset * 4;
        *packet_ptr += transport_header_length;  // Move current position by TCP header length (data offset * 4)
        
        u_short flags = data_offset_reserved_flags & 0x01FF;  // last 9 bits


        printf("%sFlags%s : ", C_LABEL, C_RESET);
        if (flags & 0x100)
            printf("NS ");
        if (flags & 0x080)
            printf("CWR ");
        if (flags & 0x040)
            printf("ECE ");
        if (flags & 0x020)
            printf("URG ");
        if (flags & 0x010)
            printf("ACK ");
        if (flags & 0x008)
            printf("PSH ");
        if (flags & 0x004)
            printf("RST ");
        if (flags & 0x002)
            printf("SYN ");
        if (flags & 0x001)
            printf("FIN ");
        if (flags == 0)
            printf("None ");

        printf("%sWindow Size%s : %d  | ", C_LABEL, C_RESET, ntohs(*(u_short*)(transport_header + 14)));
        printf("%sChecksum%s : 0x%04X  | ", C_LABEL, C_RESET, ntohs(*(u_short*)(transport_header + 16)));
        printf("%sHeader Length%s : %d bytes |\n", C_LABEL, C_RESET, transport_header_length);

    }
    else if (protocol == 17)  // UDP
    {
        /* UDP HEADER STRUCTURE : 
        { source port (2 bytes), 
            destination port (2 bytes),
            length (2 bytes),
            checksum (2 bytes) }
        */

        u_short src_port = ntohs(*(u_short*)(transport_header));
        u_short dst_port = ntohs(*(u_short*)(transport_header + 2));
        
        printf("%sSource Port%s : %d  | ", C_LABEL, C_RESET, src_port);
        printf("%sDestination Port%s : %d  | ", C_LABEL, C_RESET, dst_port);
        
        if (src_port == 80 || dst_port == 80)
            return_protocol_value = 80;
        else if (src_port == 443 || dst_port == 443)
            return_protocol_value = 443;
        else if (src_port == 53 || dst_port == 53)
            return_protocol_value = 53;
        else
            return_protocol_value = (dst_port >= 1024) ? dst_port : src_port;  // Return the higher port (likely ephemeral)
        
        printf("%sApplication Protocol%s : %s  | ", C_LABEL, C_RESET, decode_application_protocol(src_port, dst_port));
        printf("%sLength%s : %d  | ", C_LABEL, C_RESET, ntohs(*(u_short*)(transport_header + 4)));
        printf("%sChecksum%s : 0x%04X |\n", C_LABEL, C_RESET, ntohs(*(u_short*)(transport_header + 6)));

        *packet_ptr += 8;  // UDP header size = 8 bytes
    }
    else
    {
        printf("%sNo further details for this Protocol.%s\n", C_DIM, C_RESET);
    }
    return return_protocol_value;
}
   
void payload_dump(const u_char *payload, int payload_len)
{
    printf("%sPayload Data%s : ", C_LABEL, C_RESET);

    int limit;

    if (payload_len < MAX_PAYLOAD_DUMP)
    {
        printf("%s(%d bytes)%s\n\n", C_DIM, payload_len, C_RESET);
        limit = payload_len;
    }
    else 
    {
        printf("%s(First %d bytes out of %d bytes)%s\n\n", C_DIM, MAX_PAYLOAD_DUMP, payload_len, C_RESET);
        limit = MAX_PAYLOAD_DUMP;
    }

    for (int i=0; i<limit; i++) 
    {
        if (i % 16 == 0 && i != 0)
        {
            printf("   ");
            for (int j = i-16; j<i; j++)
            {
                if (payload[j] >= 32 && payload[j] <= 126)  // printable characters
                    printf("%c", payload[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
        printf("%02X ", payload[i]);

    }
    // print remaining characters in the last line
    if (limit % 16 != 0)
    {
        int blank_bytes = 16 - (limit % 16);
        for (int i=0; i<blank_bytes; i++)   // for the last line, print blank spaces for each byte left to complete 16 bytes
            printf("   ");
    }
    printf("   ");
    int start_index = limit - (limit % 16);
    if (limit % 16 == 0)
        start_index = limit - 16;

    for (int j = start_index; j<limit; j++)
    {
        if (payload[j] >= 32 && payload[j] <= 126)  // printable characters
            printf("%c", payload[j]);
        else
            printf(".");
    }
    printf("\n");

}

size_t strip_ansi_codes(const char *input, char *output, size_t output_size)
{
    size_t out_idx = 0;

    if (!input || !output || output_size == 0)
        return 0;

    for (size_t i = 0; input[i] != '\0' && out_idx + 1 < output_size; i++)
    {
        if (input[i] == '\x1b' && input[i + 1] == '[')
        {
            i += 2;
            while (input[i] != '\0' && !(input[i] >= '@' && input[i] <= '~'))
                i++;
            if (input[i] == '\0')
                break;
            continue;
        }

        output[out_idx++] = input[i];
    }

    output[out_idx] = '\0';
    return out_idx;
}