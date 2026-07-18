#include "main.h"
#include "route.h"
#include "utils.h"
#include "ui.h"
#include <signal.h>
#include <stdlib.h>

int main()
{
    ui_init();

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)   // alldevs points to head of the linked list of devices
    {
        ui_cleanup();
        fprintf(stderr, "\nError in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    if (alldevs == NULL)
    {
        ui_cleanup();
        fprintf(stderr, "No interface found! Make sure you have the necessary privileges.\n");
        return 1;
    }

    pcap_if_t *device_arr[MAX_DEVICES];
    const char *device_names[MAX_DEVICES];
    char display_names[MAX_DEVICES][256];
    int device_iterator = 0;
    
    for (pcap_if_t *d = alldevs; d != NULL && device_iterator < MAX_DEVICES; d = d->next)
    {
        device_arr[device_iterator] = d;
        if (d->description) {
            snprintf(display_names[device_iterator], 256, "%s (%s)", d->name, d->description);
        } else {
            snprintf(display_names[device_iterator], 256, "%s", d->name);
        }
        device_names[device_iterator] = display_names[device_iterator];
        device_iterator++;
    }

    while (1)
    {
        int choice = ui_select_menu("CLI-SHARK | Select a Network Interface", device_names, device_iterator);

        if (choice == -1) {
            break; // Exit
        }

        pcap_if_t *selected_device = device_arr[choice];
        work_with_device(selected_device);
    }
    
    pcap_freealldevs(alldevs);
    ui_cleanup();
    return 0;
}
