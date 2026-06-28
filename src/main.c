#include "main.h"
#include "route.h"
#include "utils.h"
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

    printf("\n%s=================================================%s\n", C_TITLE, C_RESET);
    printf("%s[CLI-SHARK]%s Your CLI Shark (not a kraken :))\n", C_ACCENT, C_RESET);
    printf("%s=================================================%s\n\n", C_TITLE, C_RESET);
    printf("%sSearching for available interfaces...%s", C_DIM, C_RESET);

    pcap_if_t *alldevs;  // pcap_if_t -> {address, flags, name, description, next}
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        fprintf(stderr, "\n%sError in pcap_findalldevs:%s %s\n", C_ERR, C_RESET, errbuf);
        return 1;
    }
    if (alldevs == NULL)
    {
        printf("%sNo interface found!%s Make sure you have the necessary privileges.\n", C_ERR, C_RESET);
        return 1;
    }

    printf("%sFound!%s\n\n", C_OK, C_RESET);
    printf("%sChoose from available interfaces:%s\n\n", C_TITLE, C_RESET);

    pcap_if_t *device_arr[MAX_DEVICES];  // to store the linked list as an array
    int device_iterator = 0;
    
    // Display available devices
    for (pcap_if_t *d = alldevs; d != NULL && device_iterator < MAX_DEVICES; d = d->next)
    {
        device_arr[device_iterator] = d;
        printf("%s%d.%s %s", C_LABEL, device_iterator + 1, C_RESET, d->name);
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
        printf("%sEnter the interface number (1-%d):%s ", C_LABEL, device_iterator, C_RESET);
        int choice_scan = scanf("%d", &choice);

        if (choice_scan == EOF)  // Ctrl+D to exit
        {
            printf("\n%sExiting...%s\n", C_WARN, C_RESET);
            break;
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
                break;
            }
            continue;
        }

        if (choice < 1 || choice > device_iterator)
        {
            printf("%sInvalid choice.%s Please try again.\n", C_ERR, C_RESET);
            continue;
        }

        pcap_if_t *selected_device = device_arr[choice - 1];
        printf("%sYou selected interface:%s %s %s\n\n\n", C_LABEL, C_RESET, selected_device->name, selected_device->description ? selected_device->description : "");
        
        // Working with the selected device
        work_with_device(selected_device);

        // When returning from work_with_device (user selected "Go Back"), redisplay the interfaces
        printf("\n");
        printf("%s=================================================%s\n", C_TITLE, C_RESET);
        printf("%sAvailable interfaces:%s\n", C_TITLE, C_RESET);
        printf("%s=================================================%s\n\n", C_TITLE, C_RESET);
        
        for (int i = 0; i < device_iterator; i++)
        {
            printf("%s%d.%s %s", C_LABEL, i + 1, C_RESET, device_arr[i]->name);
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
