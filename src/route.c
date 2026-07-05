#include "main.h"
#include "sniff.h"
#include "storage.h"
#include "report.h"
#include <signal.h>
#include "report_utils.h"
#include "utils.h"
#include "sniper.h"
#include <dirent.h>
#include "ui.h"

// Signal handler to ignore Ctrl+C in menu
void ignore_sigint_menu(int signum)
{
    (void)signum; // Suppress unused parameter warning
    // Completely ignore - do nothing, no output
}

static const char* my_fetcher(int index) {
    static char buf[256];
    stored_packet_t* stored = get_stored_packet(index);
    if (!stored) return "";
    
    // Create a one-line summary
    struct ip *iph = (struct ip *)(stored->data + 14);
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src, sizeof(src));
    inet_ntop(AF_INET, &(iph->ip_dst), dst, sizeof(dst));
    
    snprintf(buf, sizeof(buf), "[%d] %s -> %s (Len: %d)", index + 1, src, dst, stored->header.len);
    return buf;
}

static void inspect_session(const char *label)
{
    int stored_packet_count = get_stored_packet_count();
    if (stored_packet_count == 0)
    {
        ui_show_message("Inspect Session", "No packets stored from the last session.");
        return;
    }

    const char *opts[] = {
        "View Packet List",
        "View Session Dashboard",
        "Go Back"
    };

    while (1)
    {
        int ch = ui_select_menu(label, opts, 3);
        if (ch == -1 || ch == 2) break;

        if (ch == 0) {
            while (1)
            {
                int choice2 = ui_inspect_session_menu(stored_packet_count, my_fetcher);

                if (choice2 == -1)
                {
                    break;
                }

                stored_packet_t* selected_packet = get_stored_packet(choice2);
                if (selected_packet != NULL)
                {
                    char details[1024];
                    snprintf(details, sizeof(details), "Detailed packet view for packet %d\nFeature to be completed (requires rewriting report.c to return strings)", choice2 + 1);
                    
                    ui_show_packet_details(details);
                }
            }
        } else if (ch == 1) {
            session_stats_t stats;
            calculate_session_stats(&stats);
            ui_show_dashboard(&stats);
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
    const char *options[] = {
        "Start Sniffing (All Packets)",
        "Start Sniffing (With Filters)",
        "Inspect Last Session",
        "Inspect Exported Files (.pcap)",
        "Export Last Session (.pcap)",
        "Go Back (Change Interface)",
        "Exit C-Shark"
    };

    while (1)
    {
        char title[128];
        snprintf(title, sizeof(title), "What's next for %s?", device->name);
        int choice = ui_select_menu(title, options, 7);

        if (choice == -1) return; // Go back implicitly

        if (choice == 0)
        {
            sniff_packets(device, NULL);
        }
        else if (choice == 1)
        {
            char filter_exp[256] = "";
            ui_input_dialog("Enter filter (BPF syntax):", filter_exp, sizeof(filter_exp));
            if (strlen(filter_exp) > 0) {
                sniff_packets(device, filter_exp);
            }
        }
        else if (choice == 2)
        {
            inspect_session("Inspecting last session");
        }
        else if (choice == 3)
        {
            char files[128][256];
            int file_count = list_exported_pcaps(files, 128);
            if (file_count <= 0)
            {
                ui_show_message("Error", "No exported .pcap files found.");
                continue;
            }

            const char *file_options[128];
            for (int i = 0; i < file_count; i++) {
                file_options[i] = files[i];
            }

            int file_choice = ui_select_menu("Select PCAP to inspect", file_options, file_count);
            if (file_choice != -1) {
                char path[320];
                snprintf(path, sizeof(path), "exports/%s", files[file_choice]);
                if (load_session_from_pcap(path) > 0) {
                    inspect_session("Inspecting exported session");
                } else {
                    ui_show_message("Error", "Failed to load pcap file.");
                }
            }
        }
        else if (choice == 4)
        {
            if (get_stored_packet_count() == 0)
            {
                ui_show_message("Error", "No packets stored to export.");
                continue;
            }

            char filename[256] = "";
            ui_input_dialog("Enter output file name (.pcap):", filename, sizeof(filename));
            
            if (strlen(filename) > 0) {
                size_t len = strlen(filename);
                if (len < 5 || strcmp(filename + len - 5, ".pcap") != 0)
                {
                    strcat(filename, ".pcap");
                }

                if (export_session_to_pcap(filename) == 0)
                {
                    char msg[300];
                    snprintf(msg, sizeof(msg), "Session exported to exports/%s", filename);
                    ui_show_message("Success", msg);
                }
                else
                {
                    ui_show_message("Error", "Failed to export session.");
                }
            }
        }
        else if (choice == 5)
        {
            return; // Go back
        }
        else if (choice == 6)
        {
            ui_cleanup();
            exit(0);
        }
    }
}