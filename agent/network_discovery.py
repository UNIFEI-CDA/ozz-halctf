"""
Ozz — Network Discovery Module
Auto-discovers hosts and services in unknown DEF CON sandbox networks.
Handles nmap -sn (host discovery), nmap -sV (service detection),
and automatic target enumeration without prior knowledge.
"""

import ipaddress
import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ozz.netdisco")


@dataclass
class DiscoveredHost:
    """A discovered host on the network."""
    ip: str
    hostname: str = ""
    mac: str = ""
    ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    os_guess: str = ""
    alive: bool = True


@dataclass
class DiscoveredService:
    """A discovered service on a host."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class NetworkDiscovery:
    """
    Autonomous network discovery for DEF CON sandbox environments.
    
    Workflow:
    1. Detect our own network interface and subnet
    2. Sweep the subnet for live hosts (nmap -sn)
    3. For each live host, do service detection (nmap -sV)
    4. Return structured target list for the agent
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.discovered_hosts: dict[str, DiscoveredHost] = {}

    def discover_network(self, seed_target: str = "") -> list[DiscoveredHost]:
        """
        Full network discovery pipeline.
        
        Args:
            seed_target: Optional known target IP to infer subnet from.
                         If empty, auto-detects from local interfaces.
        
        Returns:
            List of discovered hosts with services.
        """
        logger.info("🔍 Starting autonomous network discovery...")

        # Step 1: Determine the attack subnet
        subnet = self._detect_subnet(seed_target)
        if not subnet:
            logger.error("Could not detect network subnet")
            return []

        logger.info(f"📡 Target subnet: {subnet}")

        # Step 2: Host discovery sweep
        live_hosts = self._host_sweep(subnet)
        logger.info(f"🏠 Found {len(live_hosts)} live hosts")

        # Step 3: Service detection on each host
        for host_ip in live_hosts:
            host = DiscoveredHost(ip=host_ip)
            services = self._service_scan(host_ip)
            host.ports = [s.port for s in services]
            host.services = {str(s.port): f"{s.service}/{s.version}" if s.version else s.service for s in services}
            self.discovered_hosts[host_ip] = host
            logger.info(f"  📍 {host_ip}: {len(services)} services — {[f'{s.port}/{s.service}' for s in services]}")

        # Step 4: Quick web fingerprinting for HTTP services
        for ip, host in self.discovered_hosts.items():
            for port in host.ports:
                if self._is_web_port(port, host.services.get(str(port), "")):
                    fingerprint = self._web_fingerprint(ip, port)
                    if fingerprint:
                        host.services[str(port)] = f"http/{fingerprint}"

        results = list(self.discovered_hosts.values())
        logger.info(f"✅ Network discovery complete: {len(results)} targets mapped")
        return results

    def _detect_subnet(self, seed_target: str = "") -> str:
        """Detect the target subnet from seed target or local interfaces."""
        if seed_target:
            try:
                network = ipaddress.ip_network(f"{seed_target}/24", strict=False)
                return str(network)
            except ValueError:
                pass

        # Auto-detect from local interfaces
        try:
            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                # Skip loopback
                if "lo" in line:
                    continue
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if match:
                    ip = match.group(1)
                    cidr = match.group(2)
                    # Skip Docker bridge and common internal ranges that aren't targets
                    if ip.startswith("172.17.") or ip.startswith("127."):
                        continue
                    network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
                    return str(network)
        except Exception as e:
            logger.warning(f"Interface detection failed: {e}")

        # Fallback: try common CTF network ranges
        for prefix in ["10.0.0", "10.10.10", "192.168.1", "172.16.0"]:
            if self._ping_check(f"{prefix}.1"):
                return f"{prefix}.0/24"

        return ""

    def _host_sweep(self, subnet: str) -> list[str]:
        """Discover live hosts using nmap ping sweep."""
        logger.info(f"🔍 Sweeping {subnet} for live hosts...")
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--min-parallelism", "64", subnet],
                capture_output=True, text=True, timeout=self.timeout
            )
            hosts = []
            for line in result.stdout.splitlines():
                match = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    hosts.append(match.group(1))
            return hosts
        except subprocess.TimeoutExpired:
            logger.warning("Host sweep timed out, trying faster approach")
            return self._fast_ping_sweep(subnet)
        except Exception as e:
            logger.error(f"Host sweep failed: {e}")
            return self._fast_ping_sweep(subnet)

    def _fast_ping_sweep(self, subnet: str) -> list[str]:
        """Fast parallel ping sweep as fallback."""
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = []
        # Ping first 254 hosts in parallel
        procs = []
        for host in network.hosts():
            if len(procs) >= 254:
                break
            proc = subprocess.Popen(
                ["ping", "-c", "1", "-W", "1", str(host)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            procs.append((str(host), proc))

        for ip, proc in procs:
            try:
                proc.wait(timeout=3)
                if proc.returncode == 0:
                    hosts.append(ip)
            except subprocess.TimeoutExpired:
                proc.kill()

        return hosts

    def _service_scan(self, host: str) -> list[DiscoveredService]:
        """Detect services on a specific host."""
        logger.info(f"🔍 Scanning services on {host}...")
        services = []
        try:
            result = subprocess.run(
                ["nmap", "-sV", "-sC", "--top-ports", "1000", "-T4",
                 "--version-intensity", "5", host],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.splitlines():
                match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
                if match:
                    port = int(match.group(1))
                    protocol = match.group(2)
                    service = match.group(3)
                    version = match.group(4).strip()
                    services.append(DiscoveredService(
                        port=port, protocol=protocol, state="open",
                        service=service, version=version
                    ))
        except subprocess.TimeoutExpired:
            logger.warning(f"Service scan timed out for {host}")
        except Exception as e:
            logger.error(f"Service scan failed for {host}: {e}")

        return services

    def _is_web_port(self, port: int, service_info: str = "") -> bool:
        """Check if a port is likely running a web service."""
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
        if port in web_ports:
            return True
        if any(kw in service_info.lower() for kw in ["http", "web", "nginx", "apache", "tomcat"]):
            return True
        return False

    def _web_fingerprint(self, host: str, port: int) -> str:
        """Quick web technology fingerprinting."""
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{host}:{port}" if port not in [80, 443] else f"{protocol}://{host}"
        try:
            result = subprocess.run(
                ["curl", "-s", "-I", "-m", "5", "-k", url],
                capture_output=True, text=True, timeout=10
            )
            headers = result.stdout
            tech = []
            if "nginx" in headers.lower():
                tech.append("nginx")
            if "apache" in headers.lower():
                tech.append("apache")
            if "php" in headers.lower():
                tech.append("php")
            if "flask" in headers.lower() or "werkzeug" in headers.lower():
                tech.append("flask")
            if "express" in headers.lower():
                tech.append("express")
            return "/".join(tech) if tech else "unknown"
        except Exception:
            return ""

    def _ping_check(self, host: str) -> bool:
        """Quick ping check."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", host],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_target_ips(self) -> list[str]:
        """Return list of discovered target IPs."""
        return list(self.discovered_hosts.keys())

    def get_targets_summary(self) -> str:
        """Human-readable summary of discovered targets."""
        lines = [f"Discovered {len(self.discovered_hosts)} targets:"]
        for ip, host in sorted(self.discovered_hosts.items()):
            ports_str = ", ".join(f"{p}/{host.services.get(str(p), '?')}" for p in host.ports)
            lines.append(f"  {ip}: [{ports_str}]")
        return "\n".join(lines)
