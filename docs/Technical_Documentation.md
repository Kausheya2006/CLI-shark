# CLI-Shark Technical Documentation

CLI-Shark is an advanced, terminal-based packet sniffer and network analysis tool. This document outlines the core architecture, data flow, and underlying mechanics of its primary modules.

---

## 1. Core Architecture and Initialization

The entry point of the application relies on `libpcap` to discover and interact with network interfaces.
- `pcap_find_alldevs()`: Finds all available network interfaces on the system.
- `route.work_with_device(pcap_if_t* selected_device)`: The main router function that dictates what actions to perform on the selected interface.

### The Main Router Flow (`route.work_with_device`)
Depending on user selection, the application follows different paths:
- **Start Sniffing (1/2)**: Calls `sniff.sniff_packets(device, filter_str | None)` to begin capturing live traffic.
- **Inspect Last Session (3)**: Calls `inspect_session()` to analyze packets currently held in memory.
- **Inspect Exported File (4)**:
  - Uses `list_exported_pcaps()` to find saved `.pcap` files in the `exports/` directory.
  - Calls `load_session_from_pcap(file_path)` to load packets into memory.
  - Proceeds to `inspect_session()`.

### Session Inspection (`route.inspect_session`)
- `get_stored_packet_count()` retrieves the number of packets currently stored in memory (`session_storage`).
- `ui_inspect_session_menu()` displays an interactive list of stored packets.
  - `my_fetcher()` is used to quickly summarize each packet (Source IP, Dest IP, Length).
- Once a user selects a packet (`choice2`), `get_stored_packet(choice2)` fetches it from `session_storage`.
- `ui_show_packet_details(packet)` handles the detailed rendering of headers and hex dumps.
- Optionally, `calculate_session_stats()` can be called to view aggregate traffic statistics.

---

## 2. Packet Capture (`sniff.c`)

The capturing mechanism relies heavily on non-blocking I/O and the `select()` system call to allow the application to simultaneously monitor incoming packets and user keyboard input.

### Capturing Flow (`sniff.sniff_packets`)
1. **Initialize & Filter**: Opens the device using `pcap_open_live()`. If a BPF (Berkeley Packet Filter) string is provided, it is compiled into bytecode using `pcap_compile()` and applied to the handle using `pcap_setfilter()`.
2. **Signal Handling**: Binds `SIGINT` (Ctrl+C) to `handle_sigint()` to cleanly break the capture loop via `pcap_breakloop(handle)`.
3. **File Descriptors**: 
   - Retrieves the standard input FD (`fileno(stdin)`) to monitor user keystrokes (like Ctrl+D).
   - Retrieves the pcap FD (`pcap_get_selectable_fd()`) to monitor incoming network packets.
4. **Non-Blocking Mode**: Sets the pcap handle to non-blocking mode (`pcap_setnonblock()`). This ensures that `pcap_dispatch()` returns immediately if no packets are available, rather than halting the entire application.

### Understanding `select()` and the Capture Loop
The `select()` system call blocks the main process and enters kernel mode, putting the process to sleep. The kernel monitors both the `stdin_fd` and `pcap_fd`. If either receives data (or a 100ms timeout occurs), the process wakes up.

```text
                             START CAPTURE
                                   │
                                   ▼
                    Open interface (pcap_open_live)
                                   │
                                   ▼
                   Set pcap handle to NON-BLOCKING
                                   │
                                   ▼
                    while (!capture_interrupted &&
                           !stdin_eof)
                                   │
                                   ▼
                    Build fd_set containing:
                       • stdin_fd
                       • pcap_fd
                                   │
                                   ▼
                      select(stdin, pcap, 100ms)
                                   │
                 ┌─────────────────┼─────────────────┐
                 │                 │                 │
                 ▼                 ▼                 ▼
          Packet arrives      Ctrl+D pressed     Nothing happens
          before timeout       before timeout      for 100 ms
                 │                 │                 │
                 ▼                 ▼                 ▼
      Kernel marks pcap_fd   Kernel marks       Timeout expires
         as READABLE         stdin READABLE     (select returns 0)
                 │                 │                 │
                 ▼                 ▼                 ▼
        select() returns    select() returns   Loop continues
                 │                 │                 │
                 ▼                 ▼                 ▼
      FD_ISSET(pcap_fd)?      FD_ISSET(stdin)?  No FD_ISSET()
            YES                    YES                │
                 │                 │                 │
                 ▼                 ▼                 ▼
      pcap_dispatch()         read(stdin)      Go back to
                 │                 │           select()
                 │                 │
        Processes ALL packets      │
      currently available          │
                 │                 │
                 ▼                 ▼
      callback(Packet 1)     read()==0 ?
      callback(Packet 2)         │
      callback(Packet 3)         │
      callback(Packet 4)         │
           ...                   │
                 │          ┌─────┴─────┐
                 ▼          │           │
     No more queued packets │           │
                 │       YES (Ctrl+D)   NO
                 ▼          │           │
      Return immediately    │     Ignore typed chars
      (because non-blocking)│           │
                 │          ▼           ▼
                 └──────► stdin_eof=1  Flush input
                            break          │
                               │           │
                               ▼           ▼
                      Exit loop      Back to select()
                                   ▲
                                   │
                      (Packet path also returns here)
```

### Packet Callback (`my_callback`)
When `pcap_dispatch` fires, it triggers `my_callback` which is provided with:
- A `pcap_pkthdr` structure containing the timestamp (`ts`), captured length (`caplen`), and original length (`len`).
- A pointer to the raw packet bytes.

> **Crucial Rule:** Always use `header->caplen` (the bytes actually available in memory) when accessing packet bytes, not `header->len` (the original size of the packet on the wire), to prevent buffer over-reads.

---

## 3. Persistent Storage & PCAP Export (`storage.c`)

CLI-Shark allows storing sessions to disk and reloading them later for inspection.

### Exporting Sessions (`export_session_to_pcap`)
- Opens a "dead" pcap handle using `pcap_open_dead()`. This is a pseudo-handle specifically used for formatting packets to a file.
- Opens the target file using `pcap_dump_open(dead, file_path)`.
- Iterates through all packets in `session_storage[]` and writes them sequentially using `pcap_dump()`.

### Loading Sessions (`load_session_from_pcap`)
- Opens a saved file using `pcap_open_offline(file_path)`.
- Enters a loop calling `pcap_next_ex()` to extract packets one-by-one.
- Stores the extracted packets into the live `session_storage[]` array.

---

## 4. AI Insights Integration (`llm.c`)

CLI-Shark integrates with local Large Language Models (LLMs) like Ollama to provide plain-english analysis of packet payloads.

```text
send_to_llm_api(raw_prompt)
        │
        ▼
escape_for_json()
        │
        ▼
Create JSON Payload
        │
        ▼
Initialize cURL
        │
        ▼
POST http://localhost:11434/api/chat
        │
        ▼
WriteMemoryCallback()
(Collect Response)
        │
        ▼
refine_response()
        │
        ▼
Extract "content"
        │
        ▼
Print AI Response
```

### The API Flow (`send_to_llm_api`)
1. **Sanitization**: Calls `escape_for_json()` to safely escape quotes, backslashes, and illegal control characters.
2. **Payload Construction**: Builds the JSON request payload targeting the `llama3` model.
3. **Transmission**: Utilizes `libcurl` to POST the payload to the local endpoint (`http://localhost:11434/api/chat`).
4. **Collection**: Uses `WriteMemoryCallback()` to stream the response chunks into a dynamically allocated buffer.
5. **Extraction**: `refine_response()` strips the JSON wrapper to locate the actual "content" response and formats `\n` and `\t` characters into literal terminal spaces.

---

## 5. TCP RST Sniper (`sniper.c`)

The sniper module allows users to forcibly terminate active TCP connections by forging and injecting TCP Reset (RST) packets into the network.

### Mechanics
- **Raw Sockets**: Bypasses the standard networking stack by utilizing raw sockets.
- **Packet Construction**: Manually builds a raw IPv4 header and a TCP header.
- **Flag Manipulation**: Sets the `TH_RST` (Reset) flag on the TCP header.
- **Kernel Override**: Enables the `IP_HDRINCL` socket option, informing the OS kernel that CLI-Shark has built the IP header manually and it should not overwrite it.
- **Injection**: Injects the forged packet via `sendto()`.

### Checksum Calculation
Forging raw packets requires manually calculating and applying network checksums to ensure intermediate routers don't drop the packet.

```text
Pseudo Header
       │
       ▼
TCP Header
       │
       ▼
Split into 16-bit words
       │
       ▼
Add all words
       │
       ▼
Fold carry bits  # in case sum exceeds 16 bits, add the carry back into the sum
       │
       ▼
Invert all bits  # 1's complement
       │
       ▼
TCP Checksum
```

---

## 6. Session Statistics Generation (`report.c`)

When navigating to the Dashboard, CLI-Shark aggregates all stored packets to calculate comprehensive networking metrics and track top communicators.

```text
                           SESSION STORAGE
                                  │
                                  ▼
                  get_stored_packet_count()
                                  │
                                  ▼
                    Total Packets = packet_count
                                  │
                                  ▼
               Loop through every stored packet (i = 0 ... N-1)
                                  │
        ┌─────────────────────────┼──────────────────────────┐
        │                         │                          │
        ▼                         ▼                          ▼
 header.len                 header.ts                 Ethernet Type
        │                         │                          │
        │                         │                          ├── 0x0800 → IPv4
        │                         │                          │        │
        │                         │                          │        ▼
        │                         │                          │   packet[23]
        │                         │                          │   (Protocol)
        │                         │                          │
        │                         │                          │   ┌────┼────┐
        │                         │                          │   │    │    │
        │                         │                          │   ▼    ▼    ▼
        │                         │                          │ TCP  UDP ICMP
        │                         │                          │ 6     17   1
        │                         │                          │ │     │     │
        │                         │                          │ ▼     ▼     ▼
        │                         │                          │TCP++ UDP++ ICMP++
        │                         │                          │
        │                         │                          │
        │                         │                          │Transport Header
        │                         │                          │
        │                         │                          ▼
        │                         │             Source Port / Destination Port
        │                         │                          │
        │                         │             ┌────────────┼────────────┐
        │                         │             │            │            │
        │                         │             ▼            ▼            ▼
        │                         │          Port 80      Port 443     Port 53
        │                         │             │            │            │
        │                         │             ▼            ▼            ▼
        │                         │         HTTP++       HTTPS++      DNS++
        │                         │
        │                         │
        │                         ▼
        │               First Packet Time
        │                       │
        │               Last Packet Time
        │                       │
        │                       ▼
        │            Duration = Last - First
        │
        ▼
Total Bytes += header.len

        │
        ▼
Read IPv4 Source IP (Bytes 26-29)
Read IPv4 Dest   IP (Bytes 30-33)

        │
        ├──────────────► Source IP
        │                  Bytes Sent += header.len
        │
        └──────────────► Destination IP
                           Bytes Recv += header.len

                                  │
                                  ▼
                     Top Talkers Table (Max 10 IPs)

                      IP | Bytes Sent | Bytes Recv
                                  │
                                  ▼
             Total Traffic = Sent + Received
                                  │
                                  ▼
          Bubble Sort (Highest Traffic → Lowest Traffic)

                                  │
                                  ▼
                     FINAL SESSION STATISTICS

   • Total Packets
   • Total Bytes
   • Session Duration
   • TCP Packets
   • UDP Packets
   • ICMP Packets
   • Other Packets
   • HTTP Connections
   • HTTPS Connections
   • DNS Connections
   • Top Talkers (sorted by Sent + Received)
```
