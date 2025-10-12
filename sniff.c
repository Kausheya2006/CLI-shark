#include "storage.h"
#include "main.h"
#include "sniff.h"


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
        printf("\n\nCtrl+C detected. Stopping packet capture and returning to menu...\n");
        capture_interrupted = 1;
        if (g_pcap_handle != NULL)
        {
            pcap_breakloop(g_pcap_handle); // Break the pcap_loop
        }
    }
}

void my_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    printf("Captured a packet of length %d
", header->len);
}

void sniff_packets(pcap_if_t *device, const char *filter_exp)
{
       
    clear_last_session(); // Clear packets from previous session to avoid memory leaks
    packet_id = 1; // Reset packet ID for new session

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf); 
    // pcap_t -> {snapshot, linktype, fd, errbuf, ...}
    // pcap_open_live -> (const char *device, int snaplen, int promisc, int to_ms, char *errbuf)  // to_ms = read timeout in milliseconds, snaplen = max bytes to capture per packet

    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, pcap_geterr(handle));
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
            fprintf(stderr, "\nCouldn't parse filter %s: %s\n\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }

        if (pcap_setfilter(handle, &fp) == -1)   // pcap_setfilter -> (pcap_t *p, struct bpf_program *fp)
        {
            fprintf(stderr, "\nCouldn't install filter %s: %s\n\n", filter_exp, pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return;
        }

        pcap_freecode(&fp); // Free the compiled filter
        printf("Filter applied: %s\n", filter_exp);
        
    }

    g_pcap_handle = handle; // Set the global pcap handle for signal handler
    capture_interrupted = 0; // Reset the interrupt flag
    stdin_eof = 0; // Reset EOF flag
    signal(SIGINT, signal_handler);  // Register signal handler for SIGINT (Ctrl+C)

    printf("\n");
    printf("========================================\n");
    printf("  STARTING PACKET CAPTURE on %s\n", device->name);
    printf("========================================\n\n\n");


    // Set stdin to non-blocking mode
    int stdin_fd = fileno(stdin);
    int pcap_fd = pcap_get_selectable_fd(handle);
    
    if (pcap_fd == -1)
    {
        fprintf(stderr, "Error: This device doesn't support select()\n");
        fprintf(stderr, "Falling back to Ctrl+C only mode...\n");
        // Fallback to pcap_loop
        pcap_loop(handle, -1, my_callback, NULL);
    }
    else
    {
        // Set pcap to non-blocking mode
        if (pcap_setnonblock(handle, 1, errbuf) == -1)
        {
            fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
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
                    printf("\n\nCtrl+D detected. Exiting program...\n");
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
                    fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
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