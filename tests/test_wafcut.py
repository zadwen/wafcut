import ipaddress
import json
from pathlib import Path
import socket
import struct
import tempfile
import types
import unittest
from unittest.mock import patch
from dnslib import DNSRecord, RCODE, RR, QTYPE, A, CNAME
from filtering import normalize_domain, matches, validate_policy, FilterResolver, DNSService
from inventory import Inventory, Vendors, validate_subnet, discover
from identity import parse_netbios_response


class RulesTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_domain('https://YouTube.COM/watch?v=x'), 'youtube.com')
        self.assertEqual(normalize_domain('*.Example.com.'), 'example.com')
        self.assertEqual(normalize_domain('bücher.de'), 'xn--bcher-kva.de')
        for value in ['127.0.0.1', 'x\ny.com', 'x.com/#\ninject', '-bad.com', 'x.com:53', 'https://a@x.com', 'single']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_suffix_boundary(self):
        self.assertTrue(matches('a.example.com.', ['example.com']))
        self.assertFalse(matches('notexample.com', ['example.com']))
        self.assertFalse(matches('example.com.evil.test', ['example.com']))

    def test_client_rules_and_allow_precedence(self):
        resolver = FilterResolver({'blocked': ['example.com'], 'clients': {
            '192.168.1.2': {'allowed': ['school.example.com'], 'blocked': ['games.test']}}}, '1.1.1.1', '192.168.1.0/24')
        self.assertTrue(resolver.blocked('video.example.com', '192.168.1.3'))
        self.assertFalse(resolver.blocked('school.example.com', '192.168.1.2'))
        self.assertTrue(resolver.blocked('games.test', '192.168.1.2'))
        self.assertFalse(resolver.blocked('games.test', '192.168.1.3'))

    def test_refusal_and_record_types(self):
        resolver = FilterResolver({'blocked': ['example.com']}, '1.1.1.1', '192.168.1.0/24')
        handler = types.SimpleNamespace(client_address=('192.168.1.2', 3333), protocol='udp')
        for kind in ['A', 'AAAA', 'HTTPS', 'TXT']:
            self.assertEqual(resolver.resolve(DNSRecord.question('example.com', kind), handler).header.rcode, RCODE.NXDOMAIN)
        handler.client_address = ('8.8.8.8', 3333)
        self.assertEqual(resolver.resolve(DNSRecord.question('example.com'), handler).header.rcode, RCODE.REFUSED)

    def test_upstream_failure_validation_cname(self):
        resolver = FilterResolver({'blocked': ['bad.test']}, '1.1.1.1', '127.0.0.0/8')
        handler = types.SimpleNamespace(client_address=('127.0.0.1', 3333), protocol='tcp')
        req = DNSRecord.question('ok.test')
        good = req.reply()
        good.add_answer(RR('ok.test', QTYPE.A, rdata=A('192.0.2.1')))
        with patch.object(DNSRecord, 'send', return_value=good.pack()):
            self.assertEqual(resolver.resolve(req, handler).header.rcode, RCODE.NOERROR)
        good.header.id ^= 1
        with patch.object(DNSRecord, 'send', return_value=good.pack()):
            self.assertEqual(resolver.resolve(req, handler).header.rcode, RCODE.SERVFAIL)
        with patch.object(DNSRecord, 'send', side_effect=TimeoutError):
            self.assertEqual(resolver.resolve(req, handler).header.rcode, RCODE.SERVFAIL)
        alias = req.reply()
        alias.add_answer(RR('ok.test', QTYPE.CNAME, rdata=CNAME('bad.test')))
        with patch.object(DNSRecord, 'send', return_value=alias.pack()):
            self.assertEqual(resolver.resolve(req, handler).header.rcode, RCODE.NXDOMAIN)

    def test_udp_tcp_and_restart(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        service = DNSService()
        for _ in range(2):
            try:
                service.start('127.0.0.1', '127.0.0.0/8', '1.1.1.1', {'blocked': ['example.com']}, port)
                for tcp in [False, True]:
                    response = DNSRecord.parse(DNSRecord.question('sub.example.com', 'AAAA').send('127.0.0.1', port, tcp=tcp, timeout=2))
                    self.assertEqual(response.header.rcode, RCODE.NXDOMAIN)
                service.resolver.set_policy({'blocked': ['other.test']})
                self.assertFalse(service.resolver.blocked('example.com', '127.0.0.1'))
            finally:
                service.stop()

    def test_partial_start_cleanup(self):
        service = DNSService()
        with socket.socket() as busy:
            busy.bind(('127.0.0.1', 0))
            busy.listen()
            port = busy.getsockname()[1]
            with self.assertRaises(OSError):
                service.start('127.0.0.1', '127.0.0.0/8', '1.1.1.1', {}, port)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1', port))
        self.assertFalse(service.servers)


class IdentityTests(unittest.TestCase):
    def test_subnet_uses_real_prefix(self):
        self.assertEqual(str(validate_subnet('192.168.2.0/23', '192.168.2.0/23')), '192.168.2.0/23')
        for subnet, connected in [('192.168.3.0/24', '192.168.2.0/24'), ('10.0.0.0/8', '10.0.0.0/8')]:
            with self.assertRaises(ValueError):
                validate_subnet(subnet, connected)

    def test_inventory_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            inv = Inventory(Path(tmp) / 'devices.json')
            ctx = {'subnet': '192.168.1.0/24'}
            inv.update(ctx, [{'ip': '192.168.1.2', 'mac': '00:11:22:33:44:55'}])
            inv.alias(ctx, '00:11:22:33:44:55', 'My laptop')
            inv.update(ctx, [{'ip': '192.168.1.3', 'mac': '00:11:22:33:44:55'}])
            rows = list(Inventory(inv.path).devices.values())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['alias'], 'My laptop')
            self.assertEqual(rows[0]['ip'], '192.168.1.3')

    def test_vendor_formats_and_private_mac(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'oui'
            path.write_text('00-11-22   (hex)   Example Manufacturer\n00:11:22:30:00:00/28 Specific Vendor\nAABBCC Other Vendor\n')
            vendors = Vendors([path])
            self.assertEqual(vendors.lookup('00:11:22:34:56:78'), 'Specific Vendor')
            self.assertEqual(vendors.lookup('00:11:22:44:56:78'), 'Example Manufacturer')
            self.assertIn('Private/local', vendors.lookup('02:11:22:44:56:78'))

    def test_cache_is_not_online(self):
        ctx = {'subnet': '192.168.1.0/24', 'iface': 'eth0', 'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55'}
        with patch('inventory.command', return_value=json.dumps([{'dst': '192.168.1.2', 'lladdr': '00:11:22:33:44:66', 'state': ['STALE']}])):
            rows = discover(ctx, ctx['subnet'], active=False)
            self.assertEqual(rows[1]['status'], 'Cached (not verified)')

    def test_netbios_without_echo_question(self):
        payload = bytes([1]) + b'MY-LAPTOP'.ljust(15) + bytes([0]) + struct.pack('>H', 0)
        packet = struct.pack('>6H', 123, 0x8400, 0, 1, 0, 0) + b'\x00' + struct.pack('>HHIH', 0x21, 1, 0, len(payload)) + payload
        self.assertEqual(parse_netbios_response(packet, 123), 'MY-LAPTOP')
        self.assertIsNone(parse_netbios_response(packet, 456))
        for end in range(len(packet)):
            self.assertIsNone(parse_netbios_response(packet[:end], 123))


if __name__ == '__main__':
    unittest.main()
