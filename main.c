#include "main.h"

#include <signal.h>

// Signal handler to ignore Ctrl+C in main menu
void ignore_sigint(int signum)
{
    (void)signum; // Suppress unused parameter warning
    // Completely ignore - do nothing, no output
}

int main()
{
    // Install signal handler to ignore Ctrl+C in main menu
    signal(SIGINT, ignore_sigint);

    printf("\n=================================================\n");
    printf("[CLI-SHARK] Your CLI Shark (not a kraken :))\n");
    printf("=================================================\n\n");
    printf("Searching for available interfaces...");

    pcap_if_t *alldevs;  // pcap_if_t -> {address, flags, name, description, next}
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        fprintf(stderr, "\nError in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    if (alldevs == NULL)
    {
        printf("No interface found! Make sure you have the necessary privileges.\n");
        return 1;
    }

    printf("Found!\n\nChoose from available interfaces: \n\n");

    pcap_if_t *device_arr[MAX_DEVICES];  // to store the linked list as an array
    int device_iterator = 0;
    
    // Display available devices
    for (pcap_if_t *d = alldevs; d != NULL && device_iterator < MAX_DEVICES; d = d->next)
    {
        device_arr[device_iterator] = d;
        printf("%d. %s", device_iterator + 1, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf("\n");
        device_iterator++;
    }
    printf("\n");
    // Main loop
    while (1)
    {
        int choice;
        printf("Enter the interface number (1-%d): ", device_iterator);
        int choice_scan = scanf("%d", &choice);

        if (choice_scan == EOF)  // Ctrl+D to exit
        {
            printf("\nExiting...\n");
            break;
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
                break;
            }
            continue;
        }

        if (choice < 1 || choice > device_iterator)
        {
            printf("Invalid choice. Please try again.\n");
            continue;
        }

        pcap_if_t *selected_device = device_arr[choice - 1];
        printf("You selected interface: %s %s\n\n\n", selected_device->name, selected_device->description ? selected_device->description : "");
        
        // Working with the selected device
        printf("Selected device: %s\n", selected_device->name);

        // When returning from work_with_device (user selected "Go Back"), redisplay the interfaces
        printf("\n");
        printf("=================================================\n");
        printf("Available interfaces:\n");
        printf("=================================================\n\n");
        
        for (int i = 0; i < device_iterator; i++)
        {
            printf("%d. %s", i + 1, device_arr[i]->name);
            if (device_arr[i]->description)
                printf(" (%s)\n", device_arr[i]->description);
            else
                printf("\n");
        }
        printf("\n");
    }
    pcap_freealldevs(alldevs);
    return 0;
}
