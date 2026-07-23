"""
scanners/nmap.py — Service detection with Nmap
"""
import xml.etree.ElementTree as ET
from utils import run_cmd, sanitize, find_bin

def scan(open_ports, timeout=120):
    """Run Nmap for service detection."""
    print("  [6/7] Nmap...", end="", flush=True)
    binary = find_bin("nmap")
    if not binary or not open_ports:
        print(" 0 services")
        return {"services": [], "service_count": 0}

    ip_ports = {}
    for p in open_ports:
        ip_ports.setdefault(p["ip"], set()).add(p["port"])
    ipv4_ips = [ip for ip in ip_ports if ":" not in ip][:15]
    if not ipv4_ips:
        print(" 0 services")
        return {"services": [], "service_count": 0}

    all_ports = set()
    for ports in ip_ports.values():
        all_ports.update(ports)
    port_spec = ",".join(str(p) for p in sorted(all_ports))

    cmd = [binary, "-4", "-sV", "--version-intensity", "3", "-T4", "-Pn",
           "-p", port_spec, "--max-retries", "1", "--host-timeout", "30s", "-oX", "-"]
    cmd.extend(ipv4_ips)
    ok, stdout, stderr = run_cmd(cmd, timeout=timeout)

    services = []
    try:
        root = ET.fromstring(stdout)
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else ""
            pe = host.find("ports")
            if pe is None:
                continue
            for port in pe.findall("port"):
                pid = port.get("portid")
                svc = port.find("service")
                if pid:
                    services.append({
                        "ip": ip, "port": int(pid),
                        "protocol": port.get("protocol", "tcp"),
                        "name": svc.get("name") if svc is not None else None,
                        "product": sanitize(svc.get("product"), 128) if svc is not None else None,
                        "version": sanitize(svc.get("version"), 128) if svc is not None else None,
                        "extra": sanitize(svc.get("extrainfo"), 10000) if svc is not None else None,
                    })
    except ET.ParseError:
        pass

    print(f" {len(services)} services")
    return {"services": services, "service_count": len(services)}
