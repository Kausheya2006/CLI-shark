#include "main.h"
#include "sniff.h"
#include "storage.h"
#include "report.h"
#include <signal.h>
#include "report_utils.h"
#include "utils.h"
#include "sniper.h"
#include <dirent.h>

// Signal handler to ignore Ctrl+C in menu
void ignore_sigint_menu(int signum)
{
    (void)signum; // Suppress unused parameter warning
    // Completely ignore - do nothing, no output
}

static void inspect_session(const char *label)
{
    printf("\n\n%s[CLI-SHARK]%s %s...\n\n\n", C_ACCENT, C_RESET, label);
    int stored_packet_count = get_stored_packet_count();
    if (stored_packet_count == 0)
    {
        printf("\n%sNo packets stored from the last session.%s\n\n", C_DIM, C_RESET);
        return;
    }

    printf("%sTotal packets stored in last session:%s %d\n", C_LABEL, C_RESET, stored_packet_count);
    printf("%s------------------------------------------------------------------------------------------------------------------------------------%s\n", C_DIM, C_RESET);
    printf("%s ID   | Timestamp         | Length | Source MAC        | Dest MAC          | Source IP       | Dest IP         | Src Port| Dst Port %s\n", C_LABEL, C_RESET);
    printf("%s------|-------------------|--------|-------------------|-------------------|-----------------|-----------------|---------|----------%s\n", C_DIM, C_RESET);
    for (int i = 0; i < stored_packet_count; i++)
    {
        stored_packet_t* stored_packet = get_stored_packet(i);
        if (stored_packet != NULL)
        {
            get_summary(stored_packet, i);
        }
    }

    printf("%s-------------------------------------------------%s\n", C_DIM, C_RESET);
    printf("%sEnd of stored packets summary.%s\n\n", C_DIM, C_RESET);

    while (1)
    {
        printf("%sEnter packet ID to view detailed info (or 0 to return to menu):%s ", C_LABEL, C_RESET);
        int choice2;
        int choice2_scan = scanf("%d", &choice2);

        if (choice2_scan == EOF)
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }

        if (choice2_scan != 1)
        {
            printf("%sInvalid input.%s Please enter a number.\n", C_ERR, C_RESET);
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            if (c == EOF)
            {
                printf("\n%sExiting...%s\n", C_WARN, C_RESET);
                exit(0);
            }
            continue;
        }

        if (choice2 == 0)
        {
            printf("%sReturning to menu...%s\n\n", C_DIM, C_RESET);
            break;
        }

        if (choice2 > 0 && choice2 <= stored_packet_count)
        {
            stored_packet_t* selected_packet = get_stored_packet(choice2 - 1);
            if (selected_packet != NULL)
            {
                int total_header_len = generate_report(selected_packet, choice2);
                printf("\n");

                char key;
                printf("\n%s[CLI-SHARK]%s Actions: [?] AI Insight | [Any] Skip: ", C_ACCENT, C_RESET);
                scanf(" %c", &key);

                if (key == '?')
                    askLLM(selected_packet, choice2, total_header_len);

                printf("\n%s[CLI-SHARK]%s Actions: [K] Kill Connection | [Any] Skip: ", C_ACCENT, C_RESET);
                scanf(" %c", &key);

                if (key == 'K' || key == 'k') {
                    struct ip *iph = (struct ip *)(selected_packet->data + 14);
                    if (iph->ip_p == IPPROTO_TCP) {

                        struct tcphdr *tcph = (struct tcphdr *)(selected_packet->data + 14 + (iph->ip_hl * 4));

                        uint32_t src_ip = iph->ip_src.s_addr;
                        uint32_t dst_ip = iph->ip_dst.s_addr;
                        uint16_t src_port = ntohs(tcph->th_sport);
                        uint16_t dst_port = ntohs(tcph->th_dport);

                        uint32_t current_seq = ntohl(tcph->th_seq);
                        uint32_t current_ack = ntohl(tcph->th_ack);

                        printf("\n%s[CLI-SHARK]%s Charging RST Sniper...\n", C_ACCENT, C_RESET);

                        fire_rst_packet(src_ip, dst_ip, src_port, dst_port, current_seq);
                        fire_rst_packet(dst_ip, src_ip, dst_port, src_port, current_ack);

                        printf("%s[CLI-SHARK]%s Target connection neutralized.\n", C_OK, C_RESET);
                    } else {
                        printf("%s[CLI-SHARK]%s Error: Sniper only works on TCP connections.\n", C_ERR, C_RESET);
                    }
                }
                printf("\n%s============================= End of Analysis =============================%s\n\n", C_TITLE, C_RESET);
            }
        }
        else
        {
            printf("%sInvalid packet ID.%s Please enter a number between 1 and %d (or 0 to return).\n", C_ERR, C_RESET, stored_packet_count);
        }
    }
}

static int list_exported_pcaps(char files[][256], int max_files)
{
    DIR *dir = opendir("exports");
    if (!dir)
        return -1;

    int count = 0;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL && count < max_files)
    {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len > 5 && strcmp(name + len - 5, ".pcap") == 0)
        {
            strncpy(files[count], name, 255);
            files[count][255] = '\0';
            count++;
        }
    }

    closedir(dir);
    return count;
}

void work_with_device(pcap_if_t *device)
{
    // Install signal handler to ignore Ctrl+C in this menu too
    signal(SIGINT, ignore_sigint_menu);

    while (1)
    {
    printf("%sWhat's next? Choose from:%s\n", C_TITLE, C_RESET);
    printf("%s1.%s Start Sniffing (All Packets)\n", C_LABEL, C_RESET);
    printf("%s2.%s Start Sniffing (With Filters)\n", C_LABEL, C_RESET);
    printf("%s3.%s Inspect Last Session\n", C_LABEL, C_RESET);
    printf("%s4.%s Inspect Exported Files (.pcap)\n", C_LABEL, C_RESET);
    printf("%s5.%s Export Last Session (.pcap)\n", C_LABEL, C_RESET);
    printf("%s6.%s Exit C-Shark\n", C_LABEL, C_RESET);
    printf("%s7.%s Go Back (Change Interface)\n", C_LABEL, C_RESET);
    printf("%sEnter your choice (1-7):%s ", C_LABEL, C_RESET);


    int choice;
    int choice_scan = scanf("%d", &choice);

    if (choice_scan == EOF)  // Ctrl+D to exit
    {
        printf("\n%sExiting...%s\n", C_WARN, C_RESET);
        exit(0);
    }

    if (choice_scan != 1)  // Invalid input (not an integer)
    {
        printf("%sInvalid input.%s Please enter a number.\n", C_ERR, C_RESET);
        // Clear the input buffer
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        if (c == EOF)  // Ctrl+D during cleanup
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }
        continue;
    }    

    if (choice == 1)
    {
        printf("%s[CLI-SHARK]%s Starting to sniff all packets on interface: %s\n", C_ACCENT, C_RESET, device->name);
        sniff_packets(device, NULL);
    }
    else if (choice == 2)
    {
        char filter_exp[256];
        printf("%sEnter filter%s (BPF syntax, e.g., 'tcp port 80'): ", C_LABEL, C_RESET);
        
        // Clear the input buffer before reading the filter string
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        if (c == EOF)  // Ctrl+D during buffer cleanup
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }

        if (scanf("%255[^\n]", filter_exp) == EOF)  // Ctrl+D while entering filter
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }

        printf("%s[CLI-SHARK]%s Starting to sniff packets with filter '%s' on interface: %s\n", C_ACCENT, C_RESET, filter_exp, device->name);
        sniff_packets(device, filter_exp);
        // After sniffing, the loop will repeat, showing the menu again.
    }
    else if (choice == 3)
    {
        inspect_session("Inspecting last session");
    }
    else if (choice == 4)
    {
        char files[128][256];
        int file_count = list_exported_pcaps(files, 128);
        if (file_count <= 0)
        {
            printf("\n%sNo exported .pcap files found in exports/.%s\n\n", C_DIM, C_RESET);
            continue;
        }

        printf("\n%sExported pcap files:%s\n", C_TITLE, C_RESET);
        for (int i = 0; i < file_count; i++)
            printf("%s%d.%s %s\n", C_LABEL, i + 1, C_RESET, files[i]);

        printf("%sSelect a file to inspect (1-%d, or 0 to cancel):%s ", C_LABEL, file_count, C_RESET);
        int file_choice = 0;
        int file_choice_scan = scanf("%d", &file_choice);
        if (file_choice_scan == EOF)
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }
        if (file_choice_scan != 1)
        {
            printf("%sInvalid input.%s Please enter a number.\n", C_ERR, C_RESET);
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            if (c == EOF)
            {
                printf("\n%sExiting...%s\n", C_WARN, C_RESET);
                exit(0);
            }
            continue;
        }
        if (file_choice == 0)
            continue;
        if (file_choice < 1 || file_choice > file_count)
        {
            printf("%sInvalid choice.%s\n", C_ERR, C_RESET);
            continue;
        }

        char path[320];
        snprintf(path, sizeof(path), "exports/%s", files[file_choice - 1]);

        if (load_session_from_pcap(path) <= 0)
        {
            printf("%s[CLI-SHARK]%s Failed to load pcap file.\n", C_ERR, C_RESET);
            continue;
        }

        inspect_session("Inspecting exported session");
    }
    else if (choice == 5)
    {
        int stored_packet_count = get_stored_packet_count();
        if (stored_packet_count == 0)
        {
            printf("\n%sNo packets stored from the last session.%s\n\n", C_DIM, C_RESET);
            continue;
        }

        char filename[256];
        printf("%sEnter output file name (.pcap):%s ", C_LABEL, C_RESET);

        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        if (c == EOF)
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }

        if (scanf("%255s", filename) == EOF)
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            exit(0);
        }

        size_t len = strlen(filename);
        if (len < 5 || strcmp(filename + len - 5, ".pcap") != 0)
        {
            if (len + 5 >= sizeof(filename))
            {
                printf("%sFile name too long.%s\n", C_ERR, C_RESET);
                continue;
            }
            strcat(filename, ".pcap");
        }

        if (export_session_to_pcap(filename) == 0)
        {
            printf("%s[CLI-SHARK]%s Session exported to exports/%s\n", C_OK, C_RESET, filename);
        }
        else
        {
            printf("%s[CLI-SHARK]%s Failed to export session.\n", C_ERR, C_RESET);
        }
    }
    else if (choice == 6)
    {
        printf("%sExiting C-Shark.%s Goodbye!\n", C_WARN, C_RESET);
        exit(0);
    }
    else if (choice == 7)
    {
        printf("%sGoing back to interface selection...%s\n\n", C_DIM, C_RESET);
        return; // Exit the loop to go back to interface selection
    }
    else
    {
        printf("%sInvalid choice.%s Returning to main menu.\n", C_ERR, C_RESET);
    }
}
}