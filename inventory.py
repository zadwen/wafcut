"""Local-only discovery and persistent device identity evidence."""
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def command(args, timeout=3):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ''


def interfaces():
    rows = json.loads(command(['ip', '-j', '-4', 'addr', 'show', 'up']) or '[]')
    routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'default']) or '[]')
    result = []
    for row in rows:
        if row['ifname'] == 'lo' or row.get('link_type') != 'ether':
            continue
        for addr in row.get('addr_info', []):
            if addr.get('scope') != 'global':
                continue
            network = ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}").network
            gateway = next((r.get('gateway', '') for r in routes if r.get('dev') == row['ifname']), '')
            result.append(dict(iface=row['ifname'], ip=addr['local'], subnet=str(network),
                               mac=row.get('address', ''), gateway=gateway))
    return result


def validate_subnet(subnet, connected):
    net = ipaddress.ip_network(subnet, strict=False)
    lan = ipaddress.ip_network(connected, strict=False)
    if net.version != 4 or not net.subnet_of(lan):
        raise ValueError('Scan range must be inside the selected interface subnet.')
    if net.num_addresses > 4096:
        raise ValueError('Choose a smaller range: at most 4096 addresses per scan.')
    return net


def discover(context, subnet, active=True):
    net = validate_subnet(subnet, context['subnet'])
    found = {}
    if active:
        from scapy.all import ARP, Ether, srp
        answers, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=str(net)),
                         iface=context['iface'], timeout=2, retry=1, inter=0.005, verbose=0)
        for _, reply in answers:
            if ipaddress.ip_address(reply.psrc) in net:
                found[reply.psrc] = dict(ip=reply.psrc, mac=reply.hwsrc.lower(), evidence='ARP reply', status='Seen')
    neighbors = json.loads(command(['ip', '-j', '-4', 'neigh', 'show', 'dev', context['iface']]) or '[]')
    for row in neighbors:
        if row.get('lladdr') and ipaddress.ip_address(row['dst']) in net:
            found.setdefault(row['dst'], dict(ip=row['dst'], mac=row['lladdr'].lower(),
                             evidence='Neighbor cache', status='Cached (not verified)'))
    if ipaddress.ip_address(context['ip']) in net:
        found[context['ip']] = dict(ip=context['ip'], mac=context['mac'].lower(),
                                  evidence='Local interface', status='This computer')
    return sorted(found.values(), key=lambda d: ipaddress.ip_address(d['ip']))


def local_names():
    result = {}
    for path in ('/var/lib/misc/dnsmasq.leases', '/var/lib/NetworkManager/dnsmasq.leases'):
        try:
            for line in Path(path).read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[3] != '*' and (int(parts[0]) == 0 or int(parts[0]) > time.time()):
                    result[(parts[2], parts[1].lower())] = parts[3]
        except (OSError, ValueError):
            pass
    return result


def lookup_name(ip):
    # Subprocess deadlines avoid changing socket defaults or hanging worker threads.
    for args, source in ((['avahi-resolve-address', '-4', ip], 'mDNS'),
                         (['getent', 'hosts', ip], 'System resolver')):
        out = command(args, timeout=1.5).splitlines()
        if out:
            parts = out[0].split()
            if len(parts) >= 2 and parts[0] == ip:
                return parts[1].rstrip('.'), source
    return '', ''


class Vendors:
    def __init__(self, paths=None):
        self.entries = {}
        paths = paths or ['/usr/share/nmap/nmap-mac-prefixes', '/usr/share/wireshark/manuf', '/var/lib/ieee-data/oui.txt']
        for path in paths:
            try:
                lines = Path(path).read_text(errors='replace').splitlines()
            except OSError:
                continue
            for line in lines:
                ieee = re.match(r'^\s*([\dA-Fa-f-]{8})\s+\(hex\)\s+(.+)$', line)
                if ieee:
                    self.entries[(int(ieee[1].replace('-', ''), 16), 24)] = ieee[2].strip()
                    continue
                parts = line.strip().split(None, 1)
                if len(parts) != 2 or parts[0].startswith('#'):
                    continue
                prefix, _, bits = parts[0].partition('/')
                prefix = prefix.replace(':', '').replace('-', '')
                if not re.fullmatch('[0-9a-fA-F]{6,12}', prefix):
                    continue
                length = int(bits) if bits.isdigit() else len(prefix) * 4
                if not 24 <= length <= 48 or length > len(prefix) * 4:
                    continue
                value = int(prefix, 16) >> (len(prefix) * 4 - length)
                vendor = parts[1].split('#')[0].strip()
                self.entries.setdefault((value, length), vendor)

    def lookup(self, mac):
        try:
            value = int(mac.replace(':', ''), 16)
            if value >> 40 & 2:
                return 'Private/local MAC — vendor unknown'
            for bits in range(48, 23, -1):
                vendor = self.entries.get((value >> (48 - bits), bits))
                if vendor:
                    return vendor
        except ValueError:
            pass
        return 'Unknown'


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.wafcut-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Inventory:
    def __init__(self, path):
        self.path = Path(path)
        self.devices = json.loads(self.path.read_text()) if self.path.exists() else {}

    @staticmethod
    def key(context, mac):
        # Avoid merging identical private MACs observed on different networks.
        return context['subnet'] + '|' + mac.lower()

    def update(self, context, rows):
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        for row in rows:
            key = self.key(context, row['mac'])
            previous = self.devices.get(key, {})
            previous.update(row)
            previous.setdefault('first_seen', now)
            previous['last_seen'] = now
            previous['network'] = context['subnet']
            self.devices[key] = previous
        atomic_json(self.path, self.devices)

    def alias(self, context, mac, name):
        self.devices[self.key(context, mac)]['alias'] = name.strip()[:100]
        atomic_json(self.path, self.devices)


def enrich(rows, vendors, netbios):
    leases = local_names()
    def one(row):
        row = dict(row)
        name = leases.get((row['ip'], row['mac']), '')
        source = 'Local DHCP lease' if name else ''
        if not name:
            name, source = lookup_name(row['ip'])
        if not name and row['status'] != 'Cached (not verified)':
            name = netbios(row['ip']) or ''
            source = 'NetBIOS' if name else ''
        row.update(name=name, name_source=source or 'Not advertised', vendor=vendors.lookup(row['mac']))
        return row
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        return list(pool.map(one, rows))
