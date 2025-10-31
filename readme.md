# 🧠 Software Switch – Layer 2 Framework

A lightweight, educational **Layer 2 Ethernet switch** built from scratch in **C** using **libpcap**.
It captures raw Ethernet frames, learns MAC addresses dynamically, and forwards frames between
interfaces — all in user space.
Think of it as your own programmable switch, running entirely in software.

## 🚀 Features

- **MAC Learning** – Dynamically builds a forwarding table (MAC → Interface mapping).
- **Frame Forwarding** – Sends packets to the correct interface if the destination is known.
- **Flooding** – Broadcasts to all interfaces except the source if destination is unknown.
- **Promiscuous Capture** – Captures all frames on each interface using libpcap.
- **Modular Design** – Cleanly separated components for maintainability.
- **Portable** – Runs on Linux or any Unix-like system with libpcap.

## 🧩 Architecture

src/
├── main.c → Initializes switch and starts pcap loops ├── packet_handler.c → Core logic for learning and forwarding frames
├── mac_table.c → Manages MAC-port mappings (hash map) ├── interface.c → Handles pcap setup, capture, and packet injection
└── utils.c → Logging and helper functions
include/ ├── switch.h
├── packet_handler.h ├── mac_table.h
├── interface.h
└── utils.h

## ⚙️ Requirements

- GCC or Clang
- libpcap development headers

### Install on Ubuntu/Debian

sudo apt updatesudo apt install libpcap-dev build-essential


## 🧪 Build and Run

### 1. Compile

make

### 2. Run

sudo ./softswitch eth1 eth2 eth

```
⚠️ You must run this as root , because raw packet capture and injection require elevated
privileges.
```
## 🧰 Example Output

[INFO] Capturing on interface: eth1[INFO] Capturing on interface: eth
[eth1] Captured frame: src=aa:bb:cc:dd:ee:ff dst=ff:ff:ff:ff:ff:ff
[SWITCH] Learned MAC aa:bb:cc:dd:ee:ff → eth1[SWITCH] Flooding frame (unknown destination)
[eth2] Forwarded frame to 11:22:33:44:55:

## 🔬 Testing in a Virtual Lab

You can simulate multiple interfaces using Linux **veth pairs** — virtual Ethernet links that behave
like physical NICs.

### Create veth pairs

sudo ip link add veth0 type veth peer name veth1sudo ip link add veth2 type veth peer name veth
sudo ip link set veth0 up
sudo ip link set veth1 upsudo ip link set veth2 up
sudo ip link set veth3 up

### Run the switch

sudo ./softswitch veth1 veth

### Assign IPs to endpoints

sudo ip addr add 10.0.0.1/24 dev veth0sudo ip addr add 10.0.0.2/24 dev veth
ping 10.0.0.2 -I veth

You’ll observe the MAC learning and frame forwarding directly in your terminal output.


## 🧩 How It Works

1. **Capture:** Each interface uses pcap_loop() to grab raw Ethernet frames.
2. **Learn:** The switch records the source MAC and maps it to the ingress interface.
3. **Forward:**
    - If the destination MAC is known → send via pcap_sendpacket() to the correct
       port.
    - If unknown → flood all other interfaces except the source.
This mimics the behavior of a **Layer 2 Ethernet switch** in the OSI model.

## 🧠 Future Enhancements

- VLAN (802.1Q) tagging and filtering
- Spanning Tree Protocol (STP) simulation
- ARP inspection and filtering
- Command-line interface for MAC table inspection
- Integration with **DPDK** for high-performance packet processing

## 🧾 License

**MIT License** — free to use, modify, and learn from.
Intended for **educational and research** purposes.

## 💬 Credits

Built by a curious engineer exploring the internals of Ethernet switching.
Inspired by classic packet sniffing examples and the elegance of libpcap.


