# CLI-Shark
CLI-Shark is a terminal-based packet sniffer and analyzer for inspecting live network traffic across common Layer 2-7 protocols, with optional AI insights.

## Features
- Live packet capture with optional BPF filters
- Detailed per-packet analysis (Ethernet, IPv4/IPv6, ARP, TCP/UDP/ICMP)
- Hex + ASCII payload dump with header highlighting
- Protocol-specific summaries (HTTP/HTTPS/DNS)
- AI insights for traffic behavior based on headers and payload
- Interactive CLI menu flow


## Run Instruction
```sh
make all  # to compile
make run  # to run the program
make clean # to remove generated files
```

## Assumptions

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
    - Layer 3 - IPv4, IPv6, ARP
    - Layer 4 :
        - ICMP, TCP, UDP for IPv4
        - ICMPv6, TCP, UDP for IPv6
    - Layer 7 :
        - HTTP, HTTPS, DNS

5. Supported Flags in TCP packets : NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN

6. **Issue :** If you press `ctrl+c` during inspect last session while providing input, it wont take you to main menu. You need to press `0` to return to main menu.
    - This is because I am assuming the document want us to handle `ctrl+c` only during packet capturing, to return it back to main menu.

7. I am not using persistant storage to save captured packets. I am storing them in an array.

## Example usage :

To test - 
1. `http` : filter - `tcp port 80`  simulate - `curl http://example.com`
2. `https` : filter - `tcp port 443`  simulate - `curl https://example.com`
3. `dns` : filter - `udp port 53`  simulate - `nslookup example.com`
4. `arp` : filter - `arp`  simulate - `arping <some-ip-in-network>`
5. `tcp` : filter - `tcp`  simulate - `telnet example.com 80`
6. `udp` : filter - `udp`  simulate - `nslookup example.com`
