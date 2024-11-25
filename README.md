## bbot-nmap-module
nmap module for the amazing scanner "bbot"

```bash
┌──(bbot)(kali㉿WSL)-[/opt/bbot]
└─$ bbot -t network-sec.de -m nmap
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.2.0

www.blacklanternsecurity.com/bbot

[INFO] Scan with 1 modules seeded with 1 targets (1 in whitelist)
[INFO] Loaded 1/1 scan modules (nmap)
[INFO] Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,excavate,speculate)
[INFO] Loaded 5/5 output modules, (csv,json,python,stdout,txt)
[WARN] Nmap requires root privileges
[USER] Please enter sudo password:
[SUCC] Authentication successful
[INFO] internal.excavate: Compiling 12 YARA rules
[SUCC] Setup succeeded for 13/13 modules.
[SUCC] Scan ready. Press enter to execute lovely_michelle

[SUCC] Scan lovely_michelle completed in 6 seconds with status FINISHED
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | Module     | Produced                   | Consumed                       |
[INFO] aggregate: +============+============================+================================+
[INFO] aggregate: | NS         | 4 (4 DNS_NAME)             | 0                              |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | speculate  | 2 (1 DNS_NAME, 1 ORG_STUB) | 7 (6 DNS_NAME, 1 IP_ADDRESS)   |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | SOA        | 1 (1 DNS_NAME)             | 0                              |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | TXT        | 1 (1 DNS_NAME)             | 0                              |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | MX         | 1 (1 DNS_NAME)             | 0                              |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | PTR        | 1 (1 DNS_NAME)             | 0                              |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | A          | 1 (1 IP_ADDRESS)           | 0                              |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | dnsresolve | 0                          | 17 (14 DNS_NAME, 3 IP_ADDRESS) |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | cloudcheck | 0                          | 13 (10 DNS_NAME, 3 IP_ADDRESS) |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
[INFO] aggregate: | nmap       | 0                          | 2 (2 DNS_NAME)                 |
[INFO] aggregate: +------------+----------------------------+--------------------------------+
```

## Changelog
- Initial commit
- Not fully tested due to nmap not working on WSL1 and currently no other options available
