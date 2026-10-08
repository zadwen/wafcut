"""Bounded name discovery without importing Scapy or accessing raw sockets."""
import socket
import struct
import random

def has_raw_socket_privilege():
    """Actually test whether we can open a raw socket, instead of just
    checking for root - this also works if cap_net_raw was granted via
    setcap without full root (see README)."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return False

def _encode_netbios_name(name):
    """NetBIOS 'half-ascii' encoding: each byte becomes two letters (A-P)."""
    return "".join(chr(0x41 + (b >> 4)) + chr(0x41 + (b & 0xF)) for b in name.encode("ascii"))

def netbios_name(ip, timeout=1.0):
    """Send an NBSTAT query (UDP/137) and pull the machine's NetBIOS name
    out of the response. Mostly useful for Windows boxes."""
    query_name = "*" + "\x00" * 15  # wildcard query, 16 bytes total
    encoded = _encode_netbios_name(query_name)

    txn_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
    question = bytes([len(encoded)]) + encoded.encode("ascii") + b"\x00"
    question += struct.pack(">HH", 0x0021, 0x0001)  # QTYPE=NBSTAT, QCLASS=IN
    packet = header + question

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, 137))
            data, peer = s.recvfrom(2048)
            if peer != (ip, 137):
                return None
    except Exception:
        return None

    return parse_netbios_response(data, txn_id)

def parse_netbios_response(data, txn_id):
    """Parse NBSTAT with or without an echoed question and validate bounds."""
    try:
        ident, flags, questions, answers, _, _ = struct.unpack_from('>6H', data)
        if ident != txn_id or not flags & 0x8000 or flags & 0xF:
            return None
        def skip_name(pos):
            for _ in range(128):
                size = data[pos]
                pos += 1
                if size == 0:
                    return pos
                if size & 0xC0 == 0xC0:
                    if pos >= len(data):
                        raise ValueError('Truncated pointer')
                    return pos + 1
                if size > 63:
                    raise ValueError('Invalid label')
                pos += size
            raise ValueError('Invalid name')
        pos = 12
        for _ in range(questions):
            pos = skip_name(pos) + 4
        for _ in range(answers):
            pos = skip_name(pos)
            kind, cls, ttl, length = struct.unpack_from('>HHIH', data, pos)
            pos += 10
            end = pos + length
            if end > len(data):
                return None
            if kind == 0x21 and cls == 1 and length:
                count = data[pos]
                pos += 1
                if pos + count * 18 > end:
                    return None
                for _ in range(count):
                    name = data[pos:pos+15].decode('ascii', errors='replace').strip()
                    suffix = data[pos+15]
                    name_flags = struct.unpack_from('>H', data, pos+16)[0]
                    if name and suffix == 0 and not name_flags & 0x8000:
                        return name
                    pos += 18
            pos = end
    except (IndexError, struct.error, ValueError):
        pass
    return None
