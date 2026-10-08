"""Desktop integration smoke test, run under Xvfb in CI."""
import os
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.environ.get('DISPLAY'), 'Requires a graphical display (CI uses Xvfb)')
class DesktopTests(unittest.TestCase):
    def test_inventory_and_policy_workflow(self):
        import tkinter as tk
        from app import WafcutApp
        root = tk.Tk()
        root.withdraw()
        ctx = dict(iface='test0', ip='192.168.1.10', subnet='192.168.1.0/24', mac='00:11:22:33:44:55', gateway='192.168.1.1')
        try:
            with tempfile.TemporaryDirectory() as tmp, patch('app.interfaces', return_value=[ctx]), patch('app.has_raw_socket_privilege', return_value=False):
                app = WafcutApp(root, tmp)
                rows = [dict(ip='192.168.1.20', mac='00:11:22:33:44:66', name='Laptop', vendor='Test', evidence='ARP reply', name_source='mDNS', status='Seen')]
                app.events.put(('scan', (ctx, rows)))
                app.poll()
                self.assertEqual(len(app.tree.get_children()), 1)
                app.tree.selection_set('0')
                with patch('app.simpledialog.askstring', return_value='My laptop'):
                    app.rename()
                self.assertEqual(app.rows[0]['alias'], 'My laptop')
                app.device_rules()
                app.blocked.insert('1.0', 'https://example.com/video')
                self.assertTrue(app.save_rules())
                self.assertEqual(app.policy['clients']['192.168.1.20']['blocked'], ['example.com'])
                app.search.set('nonexistent')
                self.assertEqual(len(app.tree.get_children()), 0)
                app.closed = True
        finally:
            root.destroy()
