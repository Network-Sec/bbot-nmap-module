## bbot-nmap-module
nmap module for the amazing scanner "bbot"

```bash
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
