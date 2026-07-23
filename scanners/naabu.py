"""
scanners/naabu.py — Port discovery with Naabu
"""
from utils import run_cmd, safe_jsonl, find_bin

def scan(live_hosts, timeout=120):
    """Run Naabu for port discovery."""
    print("  [5/7] Naabu...", end="", flush=True)
    binary = find_bin("naabu")
    if not binary:
        print(" NOT FOUND")
        return {"open_ports": [], "port_count": 0}

    hosts = [h for h in (live_hosts or []) if h.count(":") <= 1][:20]
    if not hosts:
        print(" 0 ports")
        return {"open_ports": [], "port_count": 0}

    ports = ("21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,"
             "587,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,"
             "5984,6379,6443,7001,8000,8009,8080,8081,8443,8888,9000,"
             "9090,9200,9300,11211,27017,50000")
    cmd = [binary, "-silent", "-json", "-port", ports,
           "-timeout", "10", "-rate", "1000", "-retries", "1",
           "-verify", "-scan-type", "c"]
    ok, stdout, stderr = run_cmd(cmd, timeout=timeout, stdin_text="\n".join(hosts))

    by_host = []
    seen = set()
    for row in safe_jsonl(stdout):
        ip = row.get("ip") or row.get("host")
        port = row.get("port")
        if not ip or port is None:
            continue
        host = row.get("host") or ip
        key = (host, int(port))
        if key in seen:
            continue
        seen.add(key)
        by_host.append({"host": host, "ip": ip, "port": int(port),
                        "protocol": row.get("protocol", "tcp")})

    print(f" {len(by_host)} ports")
    return {"open_ports": by_host, "port_count": len(by_host)}
