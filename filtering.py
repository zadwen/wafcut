"""Opt-in LAN DNS filtering. No traffic interception or router modification."""
import ipaddress
import re
import socket
import socketserver
import struct
import threading
from urllib.parse import urlsplit
from dnslib import DNSRecord, RCODE, QTYPE
from dnslib.server import DNSServer, DNSHandler, DNSLogger


def normalize_domain(value):
    value = value.strip()
    if not value or any(c.isspace() for c in value):
        raise ValueError('Enter one domain per line, without spaces.')
    if '://' in value:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
            raise ValueError('Only HTTP(S) URLs or domain names are accepted.')
        value = parsed.hostname or ''
    if value.startswith('*.'):
        value = value[2:]
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Use a domain name, not an IP address.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in labels):
        raise ValueError('Invalid domain: ' + value)
    return value


def matches(name, domains):
    name = name.rstrip('.').lower()
    return any(name == d or name.endswith('.' + d) for d in domains)


def validate_policy(data):
    if not isinstance(data, dict) or not isinstance(data.get('clients', {}), dict):
        raise ValueError('Invalid policy structure')
    def domains(values):
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError('Rules must be lists of domains')
        return sorted({normalize_domain(v) for v in values})
    result = {'blocked': domains(data.get('blocked', [])), 'allowed': domains(data.get('allowed', [])), 'clients': {}}
    for ip, rules in data.get('clients', {}).items():
        address = str(ipaddress.IPv4Address(ip))
        result['clients'][address] = {'blocked': domains(rules.get('blocked', [])), 'allowed': domains(rules.get('allowed', []))}
    return result


class FilterResolver:
    def __init__(self, policy, upstream, subnet):
        self.lock = threading.Lock()
        self.policy = validate_policy(policy)
        self.upstream = str(ipaddress.IPv4Address(upstream))
        self.subnet = ipaddress.IPv4Network(subnet, strict=False)
        self.stats = dict(blocked=0, forwarded=0, errors=0, refused=0)

    def set_policy(self, policy):
        policy = validate_policy(policy)
        with self.lock:
            self.policy = policy

    def snapshot(self):
        with self.lock:
            return dict(self.stats)

    def count(self, name):
        with self.lock:
            self.stats[name] += 1

    def blocked(self, name, client):
        with self.lock:
            rules = self.policy
            specific = rules['clients'].get(client, {})
            # An explicit allow overrides blocks, including inherited global blocks.
            allowed = rules['allowed'] + specific.get('allowed', [])
            blocked = rules['blocked'] + specific.get('blocked', [])
        return not matches(name, allowed) and matches(name, blocked)

    def resolve(self, request, handler):
        reply = request.reply()
        reply.header.aa = 0
        client = handler.client_address[0]
        if ipaddress.ip_address(client) not in self.subnet:
            reply.header.rcode = RCODE.REFUSED
            self.count('refused')
            return reply
        if request.header.opcode != 0 or len(request.questions) != 1 or request.q.qclass != 1 or request.q.qtype in (QTYPE.AXFR, QTYPE.IXFR, QTYPE.ANY):
            reply.header.rcode = RCODE.REFUSED
            return reply
        if self.blocked(str(request.q.qname), client):
            reply.header.rcode = RCODE.NXDOMAIN
            self.count('blocked')
            return reply
        try:
            # Connected UDP verifies the peer; transaction and question are checked below.
            if handler.protocol == 'tcp':
                raw = request.send(self.upstream, 53, tcp=True, timeout=2)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sock.connect((self.upstream, 53))
                    sock.send(request.pack())
                    raw = sock.recv(65535)
            answer = DNSRecord.parse(raw)
            if answer.header.id != request.header.id or not answer.header.qr or answer.questions != request.questions:
                raise ValueError('Invalid upstream response')
            if answer.header.tc and handler.protocol != 'tcp':
                answer = DNSRecord.parse(request.send(self.upstream, 53, tcp=True, timeout=2))
                if answer.header.id != request.header.id or not answer.header.qr or answer.questions != request.questions:
                    raise ValueError('Invalid upstream response')
            # Also apply rules to CNAME destinations visible in this response.
            if any(rr.rtype == QTYPE.CNAME and self.blocked(str(rr.rdata), client) for rr in answer.rr):
                reply.header.rcode = RCODE.NXDOMAIN
                self.count('blocked')
                return reply
            self.count('forwarded')
            return answer
        except Exception:
            reply.header.rcode = RCODE.SERVFAIL
            self.count('errors')
            return reply


class BoundedMixin(socketserver.ThreadingMixIn):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if self.slots.acquire(blocking=False):
            try:
                super().process_request(request, address)
            except Exception:
                self.slots.release()
                raise
        else:
            self.shutdown_request(request)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class UDPServer(BoundedMixin, socketserver.UDPServer):
    pass


class TCPServer(BoundedMixin, socketserver.TCPServer):
    pass


class Handler(DNSHandler):
    def handle(self):
        try:
            if self.server.socket_type == socket.SOCK_STREAM:
                self.request.settimeout(3)
                self.protocol = 'tcp'
                def read_exact(size):
                    data = b''
                    while len(data) < size:
                        chunk = self.request.recv(size - len(data))
                        if not chunk:
                            raise EOFError()
                        data += chunk
                    return data
                length = struct.unpack('!H', read_exact(2))[0]
                response = self.get_reply(read_exact(length))
                self.request.sendall(struct.pack('!H', len(response)) + response)
            else:
                super().handle()
        except (OSError, EOFError, ValueError):
            return


class DNSService:
    def __init__(self):
        self.servers = []
        self.resolver = None

    def start(self, address, subnet, upstream, policy, port=53):
        if self.servers:
            raise ValueError('DNS is already running')
        address = ipaddress.IPv4Address(address)
        network = ipaddress.IPv4Network(subnet, strict=False)
        upstream_ip = ipaddress.IPv4Address(upstream)
        if address.is_unspecified or address.is_multicast or address not in network:
            raise ValueError('Listen on a specific local IPv4 address within the allowed subnet')
        if upstream_ip == address or upstream_ip.is_unspecified or upstream_ip.is_multicast:
            raise ValueError('Choose a separate upstream DNS server')
        resolver = FilterResolver(policy, str(upstream_ip), str(network))
        created = []
        try:
            for cls, tcp in ((UDPServer, False), (TCPServer, True)):
                created.append(DNSServer(resolver, address=str(address), port=port, tcp=tcp,
                                         handler=Handler, server=cls, logger=DNSLogger(log='none')))
        except Exception:
            for server in created:
                server.server.server_close()
            raise
        for server in created:
            server.start_thread()
        self.servers, self.resolver = created, resolver

    def stop(self):
        for server in self.servers:
            server.stop()
            server.server.server_close()
        self.servers = []
        self.resolver = None
