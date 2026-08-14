# lancut

A tiny Linux tool for scanning your local network and blocking devices from it, kinda like [elmoCut](https://github.com/elmoiv/elmocut) but without the Windows-only baggage.

I wanted something like elmoCut for my own network and couldn't find a clean Linux equivalent that wasn't a full pentesting suite, so I threw this together with scapy and tkinter.

## What it does

- Scans your LAN and lists every connected device (IP + MAC)
- Lets you block a device's internet access with one click (ARP spoofing under the hood)
- Unblock puts everything back to normal
- Cleans up after itself if you close the window without unblocking manually

## What it doesn't do

No traffic sniffing, no packet dumping, no bandwidth throttling. Just block/unblock. Didn't want to build something that could snoop on other people's traffic — blocking is one thing, reading someone's data is another.

## Requirements

- Python 3
- scapy
- root (raw sockets need it)

```bash
sudo pip install scapy --break-system-packages
```

## Usage

```bash
sudo python3 lancut.py
```

Hit "Scan network", pick a device from the list, hit block/unblock. That's it.

## Heads up

Only use this on your own network / devices you actually have permission to mess with. ARP spoofing someone else's stuff without consent is illegal pretty much everywhere.

## License

MIT, see [LICENSE](LICENSE).
