import json
import ipaddress
from contextlib import suppress
from radixtarget import RadixTarget
import xml.etree.ElementTree as ET  # Correct XML parsing

from bbot.modules.base import BaseModule


class nmap(BaseModule):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS", "IP_RANGE", "DNS_NAME"]
    produced_events = ["OPEN_TCP_PORT", "SERVICE_VERSION", "UDP_OPEN_PORT"]
    meta = {
        "description": "Port scan and service detection with Nmap.",
        "created_date": "2024-11-25",
        "author": "@TheTechromancer",
    }
    options = {
        "top_ports": 1000,
        "ports": "",
        "rate": 300,
        "wait": 10,
        "ping_first": False,
        "ping_only": False,
        "service_scan": True,
        "udp_scan": False,
        "adapter": "",
    }
    options_desc = {
        "top_ports": "Top ports to scan (default 1000) (to override, specify 'ports')",
        "ports": "Ports to scan",
        "rate": "Rate of packet sending (used with ping scan only)",
        "wait": "Seconds to wait for scan completion",
        "ping_first": "Only port scan hosts that reply to pings",
        "ping_only": "Ping sweep only, no port scan",
        "service_scan": "Enable service and version detection with Nmap",
        "udp_scan": "Enable UDP scanning for open ports (can be slow)",
        "adapter": 'Specify a network interface for scanning, e.g., "eth0". Optional.',
    }
    # deps_common = ["nmap"]
    _shuffle_incoming_queue = False

    async def setup(self):
        try:
            self.top_ports = int(self.config.get("top_ports", 1000))
            self.ports = self.config.get("ports", "").strip()
            self.rate = int(self.config.get("rate", 300))
            self.wait = int(self.config.get("wait", 10))
            self.ping_first = bool(self.config.get("ping_first", False))
            self.ping_only = bool(self.config.get("ping_only", False))
            self.service_scan = bool(self.config.get("service_scan", True))
            self.udp_scan = bool(self.config.get("udp_scan", False))
            self.adapter = self.config.get("adapter", "").strip()
            self.ping_scan = self.ping_first or self.ping_only
            self.open_port_cache = {}
            self.scanned_targets = self.helpers.make_target(acl_mode=True)

            self.helpers.depsinstaller.ensure_root(message="Nmap requires root privileges")
        except Exception as e:
            self.error(f"Setup failed: {e}")
            raise
        return True

    async def handle_batch(self, *events):
        if self.ping_scan:
            ping_targets, ping_correlator = await self.make_targets(events)
            async for ip, _, parent_event in self.nmap_scan(ping_targets, ping=True):
                await self.emit_open_port(ip, 0, parent_event)
        else:
            syn_targets, syn_correlator = await self.make_targets(events)
            async for ip, port, service, parent_event in self.nmap_scan(syn_targets):
                await self.emit_open_port(ip, port, parent_event, service=service)

    async def make_targets(self, events):
        correlator = RadixTarget()
        targets = set()
        for event in events:
            if not event.host:
                continue
            ips = set()
            try:
                ips.add(ipaddress.ip_network(event.host, strict=False))
            except ValueError:
                for resolved_host in event.resolved_hosts:
                    try:
                        ips.add(ipaddress.ip_network(resolved_host, strict=False))
                    except ValueError:
                        continue
            for ip in ips:
                if self.scanned_targets.get(ip):
                    self.debug(f"Skipping {ip} - already scanned")
                    continue
                self.scanned_targets.add(ip)
                targets.add(ip)
                correlator.insert(ip, {event})
        return targets, correlator

    async def nmap_scan(self, targets, ping=False):
        if not targets:
            self.debug("No targets specified, aborting scan.")
            return

        target_file = self.helpers.tempfile(targets, pipe=False)
        command = self._build_nmap_command(target_file, ping=ping)
        try:
            async for line in self.run_process_live(command, sudo=True):
                for ip, port, service in self.parse_nmap_output(line):
                    parent_events = self.helpers.target_correlator.search(ip)
                    if parent_events is None:
                        self.debug(f"Uncorrelated result: {ip}:{port}")
                        continue
                    for parent_event in parent_events:
                        yield ip, port, service, parent_event
        finally:
            target_file.unlink()

    def _build_nmap_command(self, target_file, ping=False):
        command = ["nmap", "-oX", "-"]  # Request XML output
        if ping:
            command += ["-sn"]
        else:
            if self.ports:
                command += ["-p", self.ports]
            else:
                command += ["--top-ports", str(self.top_ports)]
            if self.service_scan:
                command += ["-sV"]
            if self.udp_scan:
                command += ["-sU"]
        command += ["-iL", str(target_file)]
        return command

    def parse_nmap_output(self, line):
        try:
            root = ET.fromstring(line)
            for host in root.findall('host'):
                ip = host.find('address').get('addr')
                for port in host.findall('ports/port'):
                    port_number = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    service = port.find('service').get('name', '')
                    if protocol == "udp":
                        yield ip, port_number, f"udp-{service}"
                    else:
                        yield ip, port_number, service
        except ET.ParseError:
            self.debug(f"Error parsing Nmap output: {line}")
            return []

    async def emit_open_port(self, ip, port, parent_event, service=None):
        data = self.helpers.make_netloc(ip, port) if port else ip
        event_type = "UDP_OPEN_PORT" if "udp" in (service or "") else "OPEN_TCP_PORT"
        context = f"Nmap scan detected {'service' if service else 'port'} on {data}"
        event = self.make_event(
            data, event_type, parent=parent_event, context=context
        )
        if service:
            event.data["service"] = service
            event.type = "SERVICE_VERSION" if "udp" not in service else event_type
        await self.emit_event(event)
        return event

    async def cleanup(self):
        self.debug("Cleaning up Nmap module")
