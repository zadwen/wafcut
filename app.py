#!/usr/bin/env python3
"""Wafcut desktop: discovery, device inventory and opt-in DNS filtering."""
import csv
import ipaddress
import json
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from inventory import interfaces, discover, enrich, Vendors, Inventory, atomic_json, validate_subnet
from filtering import DNSService, validate_policy
from identity import netbios_name, has_raw_socket_privilege


class WafcutApp:
    def __init__(self, root, data_dir=None):
        self.root = root
        self.root.title('Wafcut • Network Manager')
        self.root.geometry('1180x760')
        self.root.minsize(920, 600)
        self.data_dir = Path(data_dir or os.environ.get('WAFCUT_DATA_DIR', Path.home() / '.local/share/wafcut'))
        self.inventory = Inventory(self.data_dir / 'devices.json')
        policy_path = self.data_dir / 'policy.json'
        self.policy = validate_policy(json.loads(policy_path.read_text()) if policy_path.exists() else {})
        self.dns = DNSService()
        self.events = queue.Queue()
        self.busy = False
        self.closed = False
        self.rows = []
        self.context = None
        self.networks = interfaces()
        self.vendors = Vendors()
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', rowheight=30)
        style.configure('Title.TLabel', font=('Sans', 21, 'bold'))
        style.configure('TButton', padding=7)
        outer = ttk.Frame(root, padding=16)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='Wafcut', style='Title.TLabel').pack(anchor='w')
        ttk.Label(outer, text='Network discovery  /  Device identity  /  Website policies').pack(anchor='w', pady=(0, 12))
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill='both', expand=True)
        self.device_tab = ttk.Frame(self.tabs, padding=10)
        self.filter_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.device_tab, text='Devices')
        self.tabs.add(self.filter_tab, text='Website filtering')
        self.build_devices()
        self.build_filter()
        self.status = tk.StringVar(value='Ready. Choose your LAN interface and scan.')
        ttk.Label(outer, textvariable=self.status, wraplength=1080).pack(anchor='w', pady=(10, 0))
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.root.after(100, self.poll)

    def build_devices(self):
        toolbar = ttk.Frame(self.device_tab)
        toolbar.pack(fill='x')
        self.interface = ttk.Combobox(toolbar, state='readonly', width=36,
            values=[f"{n['iface']}  {n['ip']}  ({n['subnet']})" for n in self.networks])
        self.interface.pack(side='left')
        self.interface.bind('<<ComboboxSelected>>', self.select_interface)
        self.subnet = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.subnet, width=20).pack(side='left', padx=8)
        self.scan_button = ttk.Button(toolbar, text='Scan network', command=self.scan)
        self.scan_button.pack(side='left')
        ttk.Button(toolbar, text='Refresh interfaces', command=self.refresh_interfaces).pack(side='right')
        self.active = tk.BooleanVar(value=has_raw_socket_privilege())
        ttk.Checkbutton(self.device_tab, text='Active ARP discovery (requires raw socket permission); otherwise use neighbor cache', variable=self.active).pack(anchor='w', pady=8)
        self.search = tk.StringVar()
        ttk.Entry(self.device_tab, textvariable=self.search).pack(fill='x')
        self.search.trace_add('write', lambda *_: self.render())
        ttk.Label(self.device_tab, text='Search by name, address, manufacturer or status').pack(anchor='w')
        cols = ('ip', 'mac', 'name', 'vendor', 'evidence', 'status')
        frame = ttk.Frame(self.device_tab)
        frame.pack(fill='both', expand=True, pady=8)
        self.tree = ttk.Treeview(frame, columns=cols, show='headings', selectmode='browse')
        for col, width in zip(cols, (120, 155, 160, 210, 160, 150)):
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=width, minwidth=70)
        self.tree.pack(side='left', fill='both', expand=True)
        bar = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        bar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=bar.set)
        self.tree.bind('<Double-1>', lambda _: self.details())
        actions = ttk.Frame(self.device_tab)
        actions.pack(fill='x')
        for label, callback in [('Rename device', self.rename), ('Device details', self.details),
                                ('Export CSV', self.export), ('Website rules for device', self.device_rules)]:
            ttk.Button(actions, text=label, command=callback).pack(side='left', padx=(0, 8))
        if self.networks:
            self.interface.current(0)
            self.select_interface()

    def refresh_interfaces(self):
        if self.busy or self.dns.servers:
            messagebox.showinfo('Wafcut', 'Wait for the scan and stop DNS before changing interfaces.')
            return
        self.networks = interfaces()
        self.interface.configure(values=[f"{n['iface']}  {n['ip']}  ({n['subnet']})" for n in self.networks])
        if self.networks:
            self.interface.current(0)
            self.select_interface()
        else:
            self.interface.set('')
            self.context = None
            self.rows = []
            self.render()

    def select_interface(self, _event=None):
        index = self.interface.current()
        if index < 0:
            return
        self.context = dict(self.networks[index])
        self.subnet.set(self.context['subnet'])
        self.rows = []
        for device in self.inventory.devices.values():
            if device.get('network') == self.context['subnet']:
                self.rows.append(dict(device, status='Saved (not verified)'))
        self.render()
        if hasattr(self, 'listen'):
            self.listen.set(self.context['ip'])

    def scan(self):
        if self.busy or not self.context:
            return
        try:
            validate_subnet(self.subnet.get(), self.context['subnet'])
            if self.active.get() and not has_raw_socket_privilege():
                raise ValueError('Active discovery requires sudo. Disable active ARP for a cache-only scan.')
        except ValueError as exc:
            messagebox.showerror('Scan', str(exc))
            return
        self.busy = True
        self.scan_button.state(['disabled'])
        self.interface.configure(state='disabled')
        context, subnet, active = dict(self.context), self.subnet.get(), self.active.get()
        self.status.set(f"Scanning {subnet} on {context['iface']} — discovering and resolving names…")
        def work():
            try:
                rows = enrich(discover(context, subnet, active), self.vendors, netbios_name)
                self.events.put(('scan', (context, rows)))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        if self.closed:
            return
        try:
            while True:
                kind, payload = self.events.get_nowait()
                self.busy = False
                self.scan_button.state(['!disabled'])
                self.interface.configure(state='disabled' if self.dns.servers else 'readonly')
                if kind == 'error':
                    self.status.set('Scan failed: ' + payload)
                    messagebox.showerror('Scan', payload)
                else:
                    context, rows = payload
                    try:
                        self.inventory.update(context, rows)
                    except OSError as exc:
                        messagebox.showerror('Save inventory', str(exc))
                    fresh = {row['mac'] for row in rows}
                    self.rows = [dict(self.inventory.devices[self.inventory.key(context, row['mac'])]) for row in rows]
                    self.rows += [dict(d, status='Saved (not seen this scan)') for d in self.inventory.devices.values()
                                  if d.get('network') == context['subnet'] and d['mac'] not in fresh]
                    self.render()
                    self.status.set(f'{len(rows)} observed/cache entries. Saved devices remain visible; cached entries do not prove a device is online.')
        except queue.Empty:
            pass
        if self.dns.resolver:
            counts = self.dns.resolver.snapshot()
            self.dns_status.set('DNS running • ' + '  /  '.join(f'{k}: {v}' for k, v in counts.items()))
        self.root.after(100, self.poll)

    def render(self):
        if not hasattr(self, 'tree'):
            return
        selection = self.tree.selection()
        selected_address = tuple(self.tree.item(selection[0], 'values')[:2]) if selection else None
        self.tree.delete(*self.tree.get_children())
        query = self.search.get().lower()
        for index, row in enumerate(self.rows):
            values = (row['ip'], row['mac'], row.get('alias') or row.get('name') or 'Unknown',
                      row.get('vendor', 'Unknown'), row.get('name_source', '') + ' / ' + row.get('evidence', ''), row['status'])
            if query in ' '.join(values).lower():
                self.tree.insert('', 'end', iid=str(index), values=values)
                if values[:2] == selected_address:
                    self.tree.selection_set(str(index))
                    self.tree.focus(str(index))

    def selected(self):
        selection = self.tree.selection()
        return self.rows[int(selection[0])] if selection else None

    def rename(self):
        row = self.selected()
        if not row:
            return
        name = simpledialog.askstring('Device name', 'Custom name (empty clears it):', initialvalue=row.get('alias', ''))
        if name is not None:
            try:
                self.inventory.alias(self.context, row['mac'], name)
                row['alias'] = name.strip()[:100]
                self.render()
            except OSError as exc:
                messagebox.showerror('Save', str(exc))

    def details(self):
        row = self.selected()
        if row:
            messagebox.showinfo('Device evidence', '\n'.join(f'{k.replace("_", " ").title()}: {v}' for k, v in row.items()) +
                                '\n\nVendor is not an exact model or OS. Private MAC addresses cannot reliably identify a manufacturer.')

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if not path:
            return
        keys = ['ip', 'mac', 'alias', 'name', 'vendor', 'name_source', 'evidence', 'status', 'first_seen', 'last_seen']
        try:
            with open(path, 'w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=keys, extrasaction='ignore')
                writer.writeheader()
                for row in self.rows:
                    # Avoid spreadsheet formula execution from device-advertised names.
                    writer.writerow({k: ("'" + str(v) if str(v).startswith(('=', '+', '-', '@', '\t', '\r')) else v) for k, v in row.items()})
            self.status.set('Inventory exported: ' + path)
        except OSError as exc:
            messagebox.showerror('Export', str(exc))

    def build_filter(self):
        tab = self.filter_tab
        ttk.Label(tab, text='Block domains and their subdomains', style='Title.TLabel').pack(anchor='w')
        ttk.Label(tab, wraplength=1000, text='Devices must use this computer as their DNS server. This does not alter your router automatically. Keep this computer running; restore device DNS before stopping the service.').pack(anchor='w', pady=8)
        settings = ttk.Frame(tab)
        settings.pack(fill='x')
        self.listen = tk.StringVar(value=self.context['ip'] if self.context else '127.0.0.1')
        self.upstream = tk.StringVar(value='1.1.1.1')
        for label, var in [('Listen IPv4', self.listen), ('Upstream DNS', self.upstream)]:
            ttk.Label(settings, text=label).pack(side='left', padx=4)
            ttk.Entry(settings, textvariable=var, width=18).pack(side='left')
        self.scope = tk.StringVar(value='Global')
        scopebar = ttk.Frame(tab)
        scopebar.pack(fill='x', pady=10)
        ttk.Label(scopebar, text='Rule scope').pack(side='left')
        ttk.Entry(scopebar, textvariable=self.scope, width=22).pack(side='left', padx=8)
        ttk.Button(scopebar, text='Load scope', command=self.load_scope).pack(side='left')
        ttk.Label(scopebar, text='Global or a device IPv4 address. Save edits before changing scope.').pack(side='left', padx=8)
        editors = ttk.Frame(tab)
        editors.pack(fill='both', expand=True)
        self.blocked = tk.Text(editors, width=40, height=12, font=('Monospace', 11))
        self.allowed = tk.Text(editors, width=40, height=12, font=('Monospace', 11))
        ttk.Label(editors, text='Blocked — one domain or URL per line').grid(row=0, column=0, sticky='w')
        ttk.Label(editors, text='Allowed exceptions — override all block rules').grid(row=0, column=1, sticky='w')
        self.blocked.grid(row=1, column=0, sticky='nsew', padx=(0, 8))
        self.allowed.grid(row=1, column=1, sticky='nsew')
        editors.columnconfigure(0, weight=1)
        editors.columnconfigure(1, weight=1)
        editors.rowconfigure(1, weight=1)
        self.loaded_scope = 'Global'
        self.load_scope()
        buttons = ttk.Frame(tab)
        buttons.pack(fill='x', pady=10)
        for label, action in [('Save / apply rules', self.save_rules), ('Start DNS', self.start_dns), ('Stop DNS', self.stop_dns), ('Setup help', self.help)]:
            ttk.Button(buttons, text=label, command=action).pack(side='left', padx=(0, 8))
        self.dns_status = tk.StringVar(value='DNS stopped — rules are not enforced')
        ttk.Label(tab, textvariable=self.dns_status).pack(anchor='w')
        ttk.Label(tab, wraplength=1000, text='Limitations: VPNs, encrypted DNS, alternative IPv6 DNS, cached answers and direct IP access can bypass DNS filtering. Device rules use source IP: use DHCP reservations. No browser history is stored.').pack(anchor='w', pady=8)

    def load_scope(self):
        scope = self.scope.get().strip()
        try:
            if scope != 'Global':
                scope = str(ipaddress.IPv4Address(scope))
            rules = self.policy if scope == 'Global' else self.policy['clients'].get(scope, {})
            for widget, key in [(self.blocked, 'blocked'), (self.allowed, 'allowed')]:
                widget.delete('1.0', 'end')
                widget.insert('1.0', '\n'.join(rules.get(key, [])))
            self.loaded_scope = scope
            self.scope.set(scope)
        except ValueError as exc:
            messagebox.showerror('Scope', str(exc))

    def device_rules(self):
        row = self.selected()
        if row:
            self.scope.set(row['ip'])
            self.load_scope()
            self.tabs.select(self.filter_tab)

    def save_rules(self):
        try:
            if self.scope.get().strip() != self.loaded_scope:
                raise ValueError('Load the new scope before editing or saving its rules.')
            candidate = json.loads(json.dumps(self.policy))
            rules = candidate if self.loaded_scope == 'Global' else candidate['clients'].setdefault(self.loaded_scope, {})
            for widget, key in [(self.blocked, 'blocked'), (self.allowed, 'allowed')]:
                rules[key] = [v.strip() for v in widget.get('1.0', 'end').splitlines() if v.strip()]
            candidate = validate_policy(candidate)
            atomic_json(self.data_dir / 'policy.json', candidate)
            self.policy = candidate
            if self.dns.resolver:
                self.dns.resolver.set_policy(candidate)
            self.status.set('Rules saved' + (' and applied to running DNS.' if self.dns.servers else '. Start DNS and configure clients to enforce them.'))
            return True
        except (ValueError, OSError) as exc:
            messagebox.showerror('Rules', str(exc))
            return False

    def start_dns(self):
        if self.dns.servers or not self.save_rules():
            return
        try:
            if not self.context or self.listen.get() != self.context['ip']:
                raise ValueError('Listen address must match the selected LAN interface.')
            self.dns.start(self.listen.get(), self.context['subnet'], self.upstream.get(), self.policy)
            self.interface.configure(state='disabled')
            self.status.set('DNS started. Configure client DNS manually; see Setup help.')
        except (ValueError, OSError) as exc:
            messagebox.showerror('DNS startup', f'{exc}\n\nPort 53 requires permission and must be free on the listen address.')

    def stop_dns(self):
        if self.dns.servers and not messagebox.askyesno('Stop DNS', 'Devices using this DNS server may lose name resolution. Restore their DNS settings first. Stop now?'):
            return
        self.dns.stop()
        self.interface.configure(state='disabled' if self.busy else 'readonly')
        self.dns_status.set('DNS stopped — rules are not enforced')

    def help(self):
        messagebox.showinfo('DNS setup',
            '1. Reserve a fixed LAN IP for this computer in your router.\n'
            '2. Add domains, save rules, then start DNS.\n'
            '3. On a test device, set DNS to the listen IPv4 shown above. Do not add an unfiltered secondary DNS.\n'
            '4. For the whole LAN, configure the router DHCP DNS setting to hand out this address. Renew client leases.\n'
            '5. Allow inbound TCP and UDP port 53 only from your LAN in your firewall.\n'
            '6. Test a blocked and allowed domain. Reserve device IPs for per-device rules.\n\n'
            'Do not use your router as upstream if it forwards back here. Router DNS proxies hide individual client IPs. '
            'This service listens over IPv4; AAAA queries are filtered too, but separate IPv6 resolvers bypass it. '
            'Restore DNS before closing Wafcut. See README for commands and limitations.')

    def close(self):
        if self.dns.servers and not messagebox.askyesno('Close Wafcut', 'Closing stops DNS. Restore client DNS settings first. Close now?'):
            return
        self.closed = True
        self.dns.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        WafcutApp(root)
    except (ValueError, OSError) as exc:
        messagebox.showerror('Wafcut startup', str(exc) + '\nCheck the stored JSON configuration; it has not been overwritten.')
        root.destroy()
        return
    root.mainloop()


if __name__ == '__main__':
    main()
