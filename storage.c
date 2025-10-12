#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static stored_packet_t session_storage[MAX_PACKETS];
static int packet_count = 0;


void clear_last_session(void) 
{
    printf("Clearing last session (%d packets)...\n", packet_count);

    for (int i = 0; i < packet_count; i++) 
    {
        free(session_storage[i].data); // Free the copied packet data
        session_storage[i].data = NULL; // Avoid dangling pointer
    }
    packet_count = 0;
}


void store_packet(const struct pcap_pkthdr *header, const u_char *packet) 
{
    if (packet_count >= MAX_PACKETS) 
        return;
    

    session_storage[packet_count].data = malloc(header->caplen);

    if (session_storage[packet_count].data == NULL) 
    {
        fprintf(stderr, "Error: Failed to allocate memory for packet storage.\n");
        return;
    }

    memcpy(session_storage[packet_count].data, packet, header->caplen);  // (deep copy) {dest, src, no of bytes}

    session_storage[packet_count].header = *header;

    packet_count++;
}


int get_stored_packet_count(void) 
{
    return packet_count;
}

stored_packet_t* get_stored_packet(int packet_id) 
{
    if (packet_id < 0 || packet_id >= packet_count) 
        return NULL;

    return &session_storage[packet_id];
}