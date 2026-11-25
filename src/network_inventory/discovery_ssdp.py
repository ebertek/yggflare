"""Bounded SSDP advertisements without following device URLs."""

import ipaddress
import socket
import time


def ssdp(interface, allowed):
    """One interface-bound M-SEARCH; never fetch advertised URLs."""
    records = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0"
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.25)
        sock.sendto(
            b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
            ("239.255.255.250", 1900),
        )
        deadline = time.monotonic() + 3
        for _ in range(128):
            if time.monotonic() >= deadline:
                break
            try:
                packet, peer = sock.recvfrom(8192)
            except TimeoutError:
                continue
            if not allowed(ipaddress.ip_address(peer[0])):
                continue
            headers = {}
            for line in packet.decode("utf-8", errors="replace").splitlines()[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.lower()] = value.strip()
            # No LOCATION URL, payload fetches, cookies or arbitrary headers.
            detail = "; ".join(
                f"{k}: {headers[k][:180]}"
                for k in ("st", "usn", "server")
                if k in headers
            )
            if detail:
                records.append((peer[0], detail))
    return sorted(set(records))
