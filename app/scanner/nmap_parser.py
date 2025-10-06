import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os

def run_nmap_and_get_xml(target, extra_args=None, timeout=None):
    """
    Runs nmap -sV -oX <tmpfile> <target> and returns the path and XML contents.
    Synchronous and blocking: suitable for testing. Use with care.
    """
    args = ["nmap", "-sV", "-oX"]
    # create a temporary file to store XML output
    fd, xml_path = tempfile.mkstemp(prefix="vtr_nmap_", suffix=".xml")
    os.close(fd)
    args.append(xml_path)

    if extra_args:
        args += extra_args
    args.append(target)

    try:
        # run nmap
        subprocess.run(args, check=True, timeout=timeout)
        # read xml content
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_text = f.read()
    finally:
        # keep the xml file if you want. We return xml_text anyway.
        pass

    return xml_path, xml_text

def parse_nmap_xml(xml_text):
    """
    Parse nmap xml (string) and return list of hosts with services.
    Returns: [{ "ip": "1.2.3.4", "hostname": "host", "services": [ {port,protocol,state,service,product,version}, ... ] }, ...]
    """
    root = ET.fromstring(xml_text)
    ns = {}  # no namespace expected for nmap
    results = []
    for host in root.findall("host"):
        # fetch address (prefer ipv4)
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None

        # hostname (if any)
        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        services = []
        for port in host.findall(".//port"):
            portid = port.get("portid")
            protocol = port.get("protocol")
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None

            try:
                port_int = int(portid)
            except Exception:
                port_int = None

            services.append({
                "port": port_int,
                "protocol": protocol,
                "state": state,
                "service_name": service_name,
                "product": product,
                "version": version
            })

        if ip:
            results.append({
                "ip": ip,
                "hostname": hostname,
                "services": services
            })

    return results
