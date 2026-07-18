# CLI-Shark


![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![GNU Make](https://img.shields.io/badge/GNU%20Make-1A1A1A?style=for-the-badge&logo=gnu-make&logoColor=white)
![libpcap](https://img.shields.io/badge/libpcap-36454F?style=for-the-badge)
![Ollama](https://img.shields.io/badge/Ollama-000000?style=for-the-badge&logo=ollama&logoColor=white)

CLI-Shark is a terminal-based packet sniffer and analyzer for inspecting live network traffic across common Layer 2-7 protocols, with optional AI insights.

<table>
  <tr>
    <td><img src="assets/menu.jpeg" alt="Menu Interface" width="400"/></td>
    <td><img src="assets/dashboard.jpeg" alt="Session Dashboard" width="400"/></td>
  </tr>
  <tr>
    <td><img src="assets/header.jpeg" alt="Packet Header Details" width="400"/></td>
    <td><img src="assets/payload.jpeg" alt="Hex and ASCII Payload Dump" width="400"/></td>
  </tr>
</table>

## Features

- Live packet capture with optional BPF filters

- Detailed per-packet analysis (Ethernet, IPv4/IPv6, ARP, TCP/UDP/ICMP)

- Hex + ASCII payload dump with header highlighting

- Protocol-specific summaries (HTTP/HTTPS/DNS)

- AI insights for traffic behavior based on headers and payload

- RST sniper to neutralize TCP connections (manual action)

- Interactive CLI menu flow

- Export captured packets in pcap format

- View saved pcap files within the CLI interface

## Project Structure

```
.
├── include/
│   └── *.h
├── src/
│   ├── main.c  
│   ├── report_utils.c  
│   ├── report.c   # report generation and analysis
│   ├── route.c
│   ├── sniff.c    # for packet capturing
│   ├── storage.c
│   ├── utils.c
│   ├── llm.c       # for AI insights
│   └── sniper.c    # for RST sniper feature
├── exports/   # saved packets in pcap format
├── docs/
├── assets/
├── Makefile
├── LICENSE
└── README.md
```

## Prerequisites

Ensure the following dependencies are installed before compiling:
- **C Compiler** (e.g., `gcc` or `clang`)
- **GNU Make**
- **libpcap** (for packet capturing)
- **libcurl** (for API requests to the LLM)
- **ncurses** (for the interactive terminal UI)
- **Ollama** (optional, for AI-powered packet analysis)

## Run Instructions

```sh
make all  # to compile
make run  # to run the program
make clean # to remove generated files
```

To get AI-insight, make sure you have an ollama model running locally at `http://localhost:11434` 

```sh
ollama serve # to start the ollama server
```


## Example usage :

To test - 
1. `http` : filter - `tcp port 80`  simulate - `curl http://example.com`
2. `https` : filter - `tcp port 443`  simulate - `curl https://example.com`
3. `dns` : filter - `udp port 53`  simulate - `nslookup example.com`
4. `arp` : filter - `arp`  simulate - `arping <some-ip-in-network>`
5. `tcp` : filter - `tcp`  simulate - `telnet example.com 80`
6. `udp` : filter - `udp`  simulate - `nslookup example.com`

## Documentation

- **Architecture & Internals**: For a deep dive into the packet lifecycle, core systems, and data flow, refer to the [Technical Documentation](TECHNICAL_DOCUMENTATION.md).
- **Changelog**: Release notes and version history can be found in [Versions](docs/versions.md).

## License

This project is open-source and available under the terms of the [LICENSE](LICENSE).

## Usage Notes

1. In case of `Start Sniffing (With Filters)` option, use BPF syntax to specify the filters. Few examples include :
    ```
    tcp
    src port 80
    host 10.0.0.5
    tcp and src host 192.168.1.10 and dst port 80
    ```

2. Press `ctrl+d` anywhere to terminate the program.

3. Pressing `ctrl+c` anywhere wont terminate the program, rather :
    - stop packet capturing (if pressed during packet capture)
    - go to main menu (if pressed during packet capture or inspection)
    - Wont do anything if already at main menu or interface selection page.

4. Supported protocols for inspection : 
    ```yaml
    - Layer 3 : IPv4, IPv6, ARP
    - Layer 4 :
        - ICMP, TCP, UDP for IPv4
        - ICMPv6, TCP, UDP for IPv6
    - Layer 7 :
        - HTTP, HTTPS, DNS
    ```

5. Supported Flags in TCP packets : 
    ```yaml
    NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    ```

## Issues

- If you press `ctrl+c` during inspect last session while providing input, it wont take you to main menu. You need to press `0` to return to main menu.
