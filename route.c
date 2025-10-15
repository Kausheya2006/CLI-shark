#include "report.h"
#include "sniff.h"
#include "main.h"

#include "storage.h"

#include <signal.h>

// Signal handler to ignore Ctrl+C in menu
void ignore_sigint_menu(int signum)
{
    (void)signum; // Suppress unused parameter warning
    // Completely ignore - do nothing, no output
}

void work_with_device(pcap_if_t *device)
{
    // Install signal handler to ignore Ctrl+C in this menu too
    signal(SIGINT, ignore_sigint_menu);

    while (1)
    {
    printf("What's next? Choose from :\n");
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n"); 
    printf("4. Exit C-Shark\n");
    printf("5. Go Back (Change Interface)\n"); 
    printf("Enter your choice (1-5): ");


    int choice;
    int choice_scan = scanf("%d", &choice);

    if (choice_scan == EOF)  // Ctrl+D to exit
    {
        printf("\nExiting...\n");
        exit(0);
    }

    if (choice_scan != 1)  // Invalid input (not an integer)
    {
        printf("Invalid input. Please enter a number.\n");
        // Clear the input buffer
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        if (c == EOF)  // Ctrl+D during cleanup
        {
            printf("\nExiting...\n");
            exit(0);
        }
        continue;
    }    

    if (choice == 1)
    {
        printf("Starting to sniff all packets on interface: %s\n", device->name);
        sniff_packets(device, NULL);
    }
    else if (choice == 2)
    {
        char filter_exp[256];
        printf("Enter filter (BPF syntax, e.g., 'tcp port 80'): ");
        
        // Clear the input buffer before reading the filter string
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        if (c == EOF)  // Ctrl+D during buffer cleanup
        {
            printf("\nExiting...\n");
            exit(0);
        }

        if (scanf("%255[^\n]", filter_exp) == EOF)  // Ctrl+D while entering filter
        {
            printf("\nExiting...\n");
            exit(0);
        }

        printf("Starting to sniff packets with filter '%s' on interface: %s\n", filter_exp, device->name);
        sniff_packets(device, filter_exp);
        // After sniffing, the loop will repeat, showing the menu again.
    }
    else if (choice == 3)
    {
        printf("Inspecting last session...\n");
        int stored_packet_count = get_stored_packet_count();
        if (stored_packet_count == 0)
        {
            printf("\nNo packets stored from the last session.\n\n");
            continue;
        }

       // Replace your old header with this one
       // Replace your header with this one
        printf("Total packets stored in last session: %d\n", stored_packet_count);
        printf("------------------------------------------------------------------------------------------------------------------------------------\n");
        printf(" ID   | Timestamp         | Length | Source MAC        | Dest MAC          | Source IP       | Dest IP         | Src Port| Dst Port \n");
        printf("------|-------------------|--------|-------------------|-------------------|-----------------|-----------------|---------|----------\n");
        for (int i = 0; i < stored_packet_count; i++)
        {
            stored_packet_t* stored_packet = get_stored_packet(i);
            if (stored_packet != NULL)
            {
                get_summary(stored_packet, i);  
            }
        }

        printf("-------------------------------------------------\n");
        printf("End of stored packets summary.\n\n");
        
        // Loop to allow viewing multiple packets
        while (1)
        {
            printf("Enter packet ID to view detailed info (or 0 to return to menu): ");
            int choice2;
            int choice2_scan = scanf("%d", &choice2);

            if (choice2_scan == EOF)  // Ctrl+D to exit
            {
                printf("\nExiting...\n");
                exit(0);
            }

            if (choice2_scan != 1)  // Invalid input
            {
                printf("Invalid input. Please enter a number.\n");
                // Clear the input buffer
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
                if (c == EOF)
                {
                    printf("\nExiting...\n");
                    exit(0);
                }
                continue;
            }

            if (choice2 == 0)  // User wants to return to menu
            {
                printf("Returning to menu...\n\n");
                break;
            }

            if (choice2 > 0 && choice2 <= stored_packet_count)
            {
                // Convert from 1-indexed display ID to 0-indexed array index
                stored_packet_t* selected_packet = get_stored_packet(choice2 - 1);
                if (selected_packet != NULL)
                {
                    generate_report(selected_packet, choice2);
                    printf("\n");  // Add spacing after report
                }
            }
            else
            {
                printf("Invalid packet ID. Please enter a number between 1 and %d (or 0 to return).\n", stored_packet_count);
            }
        }
        
    }
    else if (choice == 4)
    {
        printf("Exiting C-Shark. Goodbye!\n");
        exit(0);
    }
    else if (choice == 5)
    {
        printf("Going back to interface selection...\n\n");
        return; // Exit the loop to go back to interface selection
    }
    else
    {
        printf("Invalid choice. Returning to main menu.\n");
    }
}
}