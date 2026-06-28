#include "main.h"
#include "sniff.h"
#include "utils.h"
#include "storage.h"
#include <sys/select.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>

static int packet_id = 1;

static pcap_t *g_pcap_handle = NULL; // Global pcap handle for cleanup in signal handler
static volatile sig_atomic_t capture_interrupted = 0; // Flag to track if capture was interrupted
static volatile sig_atomic_t stdin_eof = 0; // Flag to track if EOF (Ctrl+D) was detected

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        printf("\n\n%sCtrl+C detected.%s Stopping packet capture and returning to menu...\n", C_WARN, C_RESET);
        capture_interrupted = 1;
        if (g_pcap_handle != NULL)
        {
            pcap_breakloop(g_pcap_handle); // Break the pcap_loop
        }
    }
}

void my_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // pcap_pkthdr -> {ts, caplen, len}  // ts = timestamp, caplen = length of portion present, len = length of the original packet
    //                ts -> {tv_sec, tv_usec}  // tv_sec = seconds, tv_usec = microseconds
    // packet -> actual packet data
    // args -> user argument passed to pcap_loop (here, it's NULL)

    const u_char* current_pos = packet;  // This tracks the current position in packet (it will help in finding the payload starting position)

    printf("\n%s============================== PACKET %d ==============================%s\n", C_ACCENT, packet_id, C_RESET);
    printf("%s--------------------------------------------------------------------------------------%s\n", C_DIM, C_RESET);
    printf("| %sPacket ID:%s %d  | ", C_LABEL, C_RESET, packet_id);
    printf("%sTimestamp:%s %ld.%06d seconds  | ", C_LABEL, C_RESET, header->ts.tv_sec, header->ts.tv_usec);
    printf("%sCaptured Length:%s %d bytes  |\n", C_LABEL, C_RESET, header->caplen);

    printf("%s--------------------------------------------------------------------------------------%s\n\n", C_DIM, C_RESET);

    //// Layer 2 : Ethernet Header ////
    printf("%s------ L2 : Ethernet Header ------%s\n", C_SECTION, C_RESET);
    print_mac_address(packet);    // source mac, dest mac
    u_short ethertype = print_ethertype(packet);  // ethertype

    current_pos += 14;  // Move current position by 14 bytes (Ethernet header size)
    printf("\n");

    //// Layer 3 : IP Header ////
    printf("%s------ L3 : %s Header ------%s\n", C_SECTION, decode_ethertype(ethertype), C_RESET);
    u_char transport_protocol = print_ether_details(&current_pos, ethertype, packet_id);  

    printf("\n");


    if (transport_protocol == 0) 
    {
        printf("%s-------------------------------------------------%s\n\n\n", C_DIM, C_RESET);
        packet_id++;
        return;
    }

    //// Layer 4 : Transport Layer Header ////
    printf("%s------ L4 : %s Header ------%s\n", C_SECTION, decode_protocol(transport_protocol, ethertype), C_RESET);
    int application_protocol = print_L4_details(&current_pos, packet, ethertype, transport_protocol);
    printf("\n");

    //// Layer 7 : Application Layer ////

    const u_char *payload = current_pos;  // Start of the payload data
    int total_header_len = (current_pos - packet);  // Total length of all headers so far
    int payload_len = header->caplen - total_header_len;  // Length of the payload data, (caplen : captured length of packet)

    if (application_protocol == 80 || application_protocol == 443 || application_protocol == 53)  // HTTP / HTTPS / DNS
    {
         printf("%s------ L7 : Identified as [%s] Protocol on port %d  | Payload size : %d | ------%s\n", 
             C_SECTION, decode_application_protocol(application_protocol, application_protocol), application_protocol, payload_len, C_RESET);
        printf("\n");

        if (payload_len > 0)
        {
            payload_dump(payload, payload_len);
            printf("\n");
        }
        else
        {
            printf("%sNo Payload Data.%s\n\n", C_DIM, C_RESET);
        }
    }
    else if (application_protocol > 0)  // Valid port but not a known protocol
    {
        printf("%s------ L7 : Unidentified Application Protocol on non-standard port %d  | Payload size : %d | ------%s\n", C_SECTION, application_protocol, payload_len, C_RESET);
        printf("%sNo further details for this Application Protocol.%s\n\n", C_DIM, C_RESET);
    }
    else  // Port 0 means not TCP/UDP or error
    {
        printf("%s------ L7 : No transport layer or unsupported protocol | Payload size : %d | ------%s\n", C_SECTION, payload_len, C_RESET);
        printf("%sNo further details available.%s\n\n", C_DIM, C_RESET);
    }

    // Store the packet in session storage
    store_packet(header, packet);

    packet_id++;
    printf("%s--------------------------------------------------------------------------------------%s\n", C_DIM, C_RESET);
    printf("%s============================ END PACKET %d ============================%s\n\n", C_ACCENT, packet_id, C_RESET);


}

void sniff_packets(pcap_if_t *device, const char *filter_exp)
{
       
    clear_last_session(); // Clear packets from previous session to avoid memory leaks
    packet_id = 1; // Reset packet ID for new session

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf); 
    // pcap_t -> {snapshot, linktype, fd, errbuf, ...}
    // pcap_open_live -> (const char *device, int snaplen, int promisc, int to_ms, char *errbuf)  // to_ms = read timeout in milliseconds, snaplen = max bytes to capture per packet

    int link_type = pcap_datalink(handle);
    if (link_type == DLT_NULL) {
        // This is macOS Loopback! Use a 4-byte offset
    } else if (link_type == DLT_EN10MB) {
        // This is standard Ethernet! Use a 14-byte offset
    }
    
    if (handle == NULL) 
    {
        fprintf(stderr, "%sCouldn't open device %s:%s %s\n", C_ERR, device->name, C_RESET, pcap_geterr(handle));
        return;
    }

    if (filter_exp != NULL)
    {
        struct bpf_program fp; // Berkeley Packet Filter
        // bpf_program -> {bf_len, bf_insns}  // bf_len = number of instructions, bf_insns = pointer to array of instructions
        //                bpf_insn -> {code, jt, jf, k}  // code = opcode, jt = jump true, jf = jump false, k = generic field

        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)    // pcap_compile -> (pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask) // optimize : means whether to optimize the compiled code
        // this compiles the filter expression into BPF bytecode
        {
            fprintf(stderr, "\n%sCouldn't parse filter %s:%s %s\n\n", C_ERR, filter_exp, C_RESET, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }

        if (pcap_setfilter(handle, &fp) == -1)   // pcap_setfilter -> (pcap_t *p, struct bpf_program *fp)
        {
            fprintf(stderr, "\n%sCouldn't install filter %s:%s %s\n\n", C_ERR, filter_exp, C_RESET, pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return;
        }

        pcap_freecode(&fp); // Free the compiled filter
        printf("%sFilter applied:%s %s\n", C_OK, C_RESET, filter_exp);
        
    }

    g_pcap_handle = handle; // Set the global pcap handle for signal handler
    capture_interrupted = 0; // Reset the interrupt flag
    stdin_eof = 0; // Reset EOF flag
    signal(SIGINT, signal_handler);  // Register signal handler for SIGINT (Ctrl+C)

    printf("\n");
    printf("%s========================================%s\n", C_TITLE, C_RESET);
    printf("%s  STARTING PACKET CAPTURE on %s%s\n", C_TITLE, device->name, C_RESET);
    printf("%s========================================%s\n\n\n", C_TITLE, C_RESET);


    // Set stdin to non-blocking mode
    int stdin_fd = fileno(stdin);
    int pcap_fd = pcap_get_selectable_fd(handle);
    
    if (pcap_fd == -1)
    {
        fprintf(stderr, "%sError:%s This device doesn't support select()\n", C_ERR, C_RESET);
        fprintf(stderr, "%sFalling back to Ctrl+C only mode...%s\n", C_WARN, C_RESET);
        // Fallback to pcap_loop
        pcap_loop(handle, -1, my_callback, NULL);
    }
    else
    {
        // Set pcap to non-blocking mode
        if (pcap_setnonblock(handle, 1, errbuf) == -1)
        {
            fprintf(stderr, "%sError setting non-blocking mode:%s %s\n", C_ERR, C_RESET, errbuf);
            pcap_close(handle);
            return;
        }

        // Main capture loop using select()
        while (!capture_interrupted && !stdin_eof)
        {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(stdin_fd, &readfds);
            FD_SET(pcap_fd, &readfds);

            int max_fd = (stdin_fd > pcap_fd) ? stdin_fd : pcap_fd;
            
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000; // 100ms timeout

            int ret = select(max_fd + 1, &readfds, NULL, NULL, &timeout);

            if (ret == -1)
            {
                if (errno == EINTR) // Interrupted by signal (Ctrl+C)
                    continue;
                perror("select");
                break;
            }

            // Check if stdin has data (Ctrl+D detection)
            if (FD_ISSET(stdin_fd, &readfds))
            {
                char c;
                int n = read(stdin_fd, &c, 1);
                if (n == 0) // EOF detected (Ctrl+D)
                {
                    printf("\n\n%sCtrl+D detected.%s Exiting program...\n", C_WARN, C_RESET);
                    stdin_eof = 1;
                    break;
                }
                else if (n > 0)
                {
                    // User typed something - ignore it during capture
                    // Clear any remaining input
                    while (read(stdin_fd, &c, 1) > 0);
                }
            }

            // Check if pcap has packets
            if (FD_ISSET(pcap_fd, &readfds))
            {
                // Process available packets
                int packet_count = pcap_dispatch(handle, -1, my_callback, NULL);
                if (packet_count == -1)
                {
                    fprintf(stderr, "%sError reading packets:%s %s\n", C_ERR, C_RESET, pcap_geterr(handle));
                    break;
                }
            }
        }
    }

    // Restore menu signal handler after capture (not default which would terminate)
    // We'll let the calling function (work_with_device) handle reinstalling its own handler
    extern void ignore_sigint_menu(int);
    signal(SIGINT, ignore_sigint_menu);

    pcap_close(handle);
    g_pcap_handle = NULL; // Clear the global pcap handle

    if (capture_interrupted)
    {
        printf("\nPacket capture stopped. Returning to menu...\n\n");
    }
    else if (stdin_eof)
    {
        // Exit the entire program
        printf("Goodbye!\n");
        exit(0);
    }
}