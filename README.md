# Wafcut — LAN inventory and website filtering

A Linux desktop network manager with evidence-based device identification and an
opt-in DNS filtering service. Inspired by the clarity of Fing's inventory workflow;
this project does **not** use Fing's proprietary recognition database or claim its
model-identification coverage.

## What's new

- Select a real Ethernet/Wi-Fi interface and discover its actual IPv4 subnet instead
  of assuming `/24`. Restrict a scan to a smaller range if needed (4096-address cap).
- Retried ARP discovery, neighbor-cache fallback, local-computer entry and explicit
  **Seen / Cached / Saved** states. Cached/saved entries are not reported as online.
- Names from local dnsmasq leases, mDNS through Avahi, system name resolution and
  corrected NetBIOS node-status parsing. Twelve bounded name-resolution workers.
- Offline vendor lookup from Nmap, Wireshark or IEEE data, including longer MAC
  prefixes. Private/local MAC addresses are labeled rather than assigned false vendors.
- Persistent custom names, first/last observation times, searchable inventory,
  device evidence, and CSV export with spreadsheet formula neutralization.
- Global and per-device domain/subdomain block rules, allow exceptions, URL/IDN
  normalization, persistent policies and live rule reload.
- Explicitly started DNS server supporting UDP and TCP, A/AAAA/HTTPS and other
  ordinary queries, CNAME checks, LAN client restrictions, upstream validation,
  deadlines, bounded request workers, counters and clean socket shutdown.
- Local storage only; no browsing-history logs and no online vendor API calls.
- Automated unit tests and loopback DNS integration tests; GitHub Actions workflow.

## Install (Zorin / Ubuntu / Debian / Kali)

Python 3.10+ is required.

```bash
sudo apt update
sudo apt install python3-venv python3-tk iproute2 avahi-utils ieee-data dnsutils
git clone https://github.com/zadwen/wafcut.git
cd wafcut
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

For a cache-only scan and saved inventory (no root):

```bash
.venv/bin/python app.py
```

For active ARP discovery and binding DNS port 53:

```bash
sudo .venv/bin/python app.py
```

`python lancut.py` also opens the new app. Keep the same launch mode so you keep the
same inventory: regular-user and root home directories differ. An explicit data
location can be selected with `WAFCUT_DATA_DIR`; it must be writable by the process.
Do not grant network capabilities to a general-purpose Python interpreter.

The GUI runs with the privileges you give it. A separate privileged helper is a
future hardening task. On Wayland, if sudo cannot open a graphical window, use your
distribution's supported graphical administrative launcher; do not disable desktop
access controls. Cache-only mode remains available without root.

## Device identification

1. Choose your LAN interface (not a VPN). The range comes from its configured prefix.
2. Click **Scan network**. Active scanning requires raw socket permission.
3. Search by IP, MAC, name, vendor or status. Double-click for identification evidence.
4. Use **Rename device** to save a known label. Labels follow the MAC within the subnet,
   so an IP change normally preserves the name. A changed private MAC creates a new
   identity; the app deliberately does not guess that two MACs belong to one device.

**Unknown does not mean an error or an intruder.** Phones may use private MACs and
publish no hostname. Sleeping devices, guest Wi-Fi isolation, different VLANs,
firewalls and IPv6-only devices may not answer IPv4 ARP discovery. This release has
IPv4 inventory; it does not implement active IPv6 neighbor discovery. The local
computer cannot read DHCP leases stored only on your router. Install a vendor data
package and Avahi tools for more naming evidence. Exact model/OS fingerprinting is
not implemented. Names and vendors are evidence, not proof of ownership.

## Block websites

This is a DNS service on your computer, **not** transparent interception. Adding a
rule alone does not change what any other device can reach.

1. Reserve a stable IPv4 address for the Wafcut computer in your router.
2. Open **Website filtering**. Enter a root domain such as `youtube.com` in **Blocked**.
   Its subdomains (e.g. `www.youtube.com`) are included. URLs are reduced to their
   hostname, not their full path. `notyoutube.com` does not match `youtube.com`.
3. Add exceptions to **Allowed** if required. Allow rules override block rules.
4. Save, choose a separate upstream resolver, and click **Start DNS**. Default upstream
   is Cloudflare `1.1.1.1`; forwarded queries go to the selected resolver unencrypted.
   Do not use an upstream router that forwards DNS back to Wafcut (a forwarding loop).
5. On one test device set DNS to the Wafcut computer's LAN IPv4. For network-wide
   setup, configure your router's **DHCP DNS** setting to distribute this address,
   then renew device leases. Some routers lack this option.
6. Permit TCP **and** UDP port 53 from your LAN in your firewall. Do not port-forward
   this service to the internet. The app does not modify firewall rules.
7. Test both blocked and allowed names; replace the example IP below:

   ```bash
   dig @192.168.1.10 youtube.com A
   dig @192.168.1.10 youtube.com AAAA +tcp
   dig @192.168.1.10 example.org A
   ```

   Blocked names return `NXDOMAIN`; unblocked names should resolve normally. If they
   return `SERVFAIL`, check upstream reachability and the error counter.

For a device-specific rule, select it in Devices and click **Website rules for
device**, or enter its IPv4 as the scope and click **Load scope**. Save before changing
scope. Use DHCP reservations: rules bind to source IPv4, not to a MAC. Global rules
are inherited; global and device allow exceptions override both sets of blocks.
If the router proxies DNS, Wafcut sees the router's IP and cannot distinguish clients.

Keep Wafcut and its computer running while clients depend on it. **Restore their DNS
settings before stopping or closing it.** There is no automatic router rollback,
background service installation or failover setup in this release.

### Filtering limits

- Domain rules are not URL-path rules. You cannot block one video or page while
  allowing other pages on the same hostname.
- Apps often use several domains/CDNs. Add the actual required domains; a single
  website domain is not a complete app-specific blocklist.
- VPNs, browser Secure DNS/DoH, Android Private DNS/DoT, other resolvers, IPv6 DNS,
  existing cached answers/connections and direct IP access can bypass this filter.
- The listener is IPv4; it filters AAAA requests received over IPv4 but does not
  provide an IPv6 DNS listener. IPv6-only clients are not supported in this release.
- Reliable enforced filtering requires router/firewall policy and managed endpoints.
  This app does not promise unbypassable blocking and does not inspect HTTPS contents.
- DNSSEC is passed through from upstream; Wafcut does not independently validate it.
  Policy-generated negative answers are not signed. No DNS response cache is added.
- This is a desktop LAN utility, not a production recursive resolver or a Fing clone.

## Original device disconnect mode

The existing ARP-based block/unblock UI remains available separately:

```bash
sudo .venv/bin/python lancut.py --legacy
```

It is retained for compatibility, with duplicate-block protection and corrected
NetBIOS parsing. It does not provide website-selective filtering or IPv6 blocking,
and its original scan UI still has a `/24` assumption. Use the new UI for inventory.
ARP manipulation can interrupt connectivity and may not work on networks with ARP
protection; use it only on networks you administer. A router's own access controls
are preferable for sustained device restrictions. Do not combine legacy disconnect
mode with DNS filtering for the same client.

## Data, tests and troubleshooting

Files: `~/.local/share/wafcut/devices.json` and `policy.json`, under the account that
launches the app. Writes are atomic. Back these up before moving between accounts.
A malformed JSON file causes an explicit startup error instead of silently resetting
it. The files contain local device addresses and names; treat exported inventory as
private network information.

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Tests cover domain boundaries, per-client rules, allow precedence, upstream errors
and validation, CNAME policies, UDP/TCP serving and restart, partial-bind cleanup,
subnet validation, inventory persistence, vendor formats, cache states and malformed
NetBIOS responses. A desktop workflow smoke test runs under Xvfb in CI and is
skipped locally when no graphical display is available. They don't require external DNS or scan a real LAN.

If port 53 is busy, inspect `sudo ss -lntup 'sport = :53'`. Bind to the computer's
specific LAN address; do not disable the system resolver blindly. A service bound to
all addresses can still conflict. If network settings change, stop DNS, refresh
interfaces, then update clients before starting on a different IP.

## References

- [Fing: device recognition](https://help.fing.com/hc/en-us/articles/23718945251356-Device-Recognition)
- [Fing: private MAC addressing](https://help.fing.com/hc/en-us/articles/14557409680412-MAC-Addresses-and-Private-Addressing)
- [Avahi address resolution](https://manpages.debian.org/bookworm/avahi-utils/avahi-resolve.1.en.html)
- [dnslib protocol library](https://github.com/paulc/dnslib)
- [dnsmasq documentation: local DNS/DHCP and domain matching](https://dnsmasq.org/docs/dnsmasq-man.html)

MIT license; see [LICENSE](LICENSE).
