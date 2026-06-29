#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

static stored_packet_t session_storage[MAX_PACKETS];
static int packet_count = 0;
static int session_linktype = DLT_EN10MB; 


void clear_last_session(void) 
{
    printf("Clearing last session (%d packets)...\n", packet_count);

    for (int i = 0; i < packet_count; i++) 
    {
        free(session_storage[i].data); // Free the copied packet data
        session_storage[i].data = NULL; // Avoid dangling pointer
    }
    packet_count = 0;
    session_linktype = DLT_EN10MB;
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

void set_session_linktype(int linktype)
{
    session_linktype = linktype;
}

int export_session_to_pcap(const char *path)
{
    if (!path || path[0] == '\0')
        return -1;

    if (mkdir("exports", 0755) != 0 && errno != EEXIST)
        return -1;

    char full_path[512];
    if (snprintf(full_path, sizeof(full_path), "exports/%s", path) >= (int)sizeof(full_path))
        return -1;

    pcap_t *dead = pcap_open_dead(session_linktype, 65535);  
    if (!dead)
        return -1;

    pcap_dumper_t *dumper = pcap_dump_open(dead, full_path);
    if (!dumper)
    {
        pcap_close(dead);
        return -1;
    }

    for (int i = 0; i < packet_count; i++)
        pcap_dump((u_char *)dumper, &session_storage[i].header, session_storage[i].data);

    pcap_dump_close(dumper);
    pcap_close(dead);
    return 0;
}

int load_session_from_pcap(const char *path)
{
    if (!path || path[0] == '\0')
        return -1;

    clear_last_session();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(path, errbuf);
    if (!handle)
        return -1;

    session_linktype = pcap_datalink(handle);

    struct pcap_pkthdr *header = NULL;
    const u_char *packet = NULL;
    int status = 0;

    while ((status = pcap_next_ex(handle, &header, &packet)) == 1)
        store_packet(header, packet);

    pcap_close(handle);

    if (status == -1)
    {
        clear_last_session();
        return -1;
    }

    return packet_count;
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