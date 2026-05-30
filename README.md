# NetDevs Pro — Packet Injection Backend

The NetDevs Pro Backend is a high-performance, asynchronous Python service designed to bridge the gap between the browser-based UI and the system's network stack. It provides raw socket capabilities to inject hand-crafted Layer 3 and Layer 4 packets directly onto the local network.

---

## 🚀 Key Features

- **Raw Socket Injection**: Manual header construction for IPv4, TCP, and UDP.
- **Asynchronous Engine**: Built on `asyncio` and `websockets` for high concurrency.
- **Cross-Platform**: Tested on Linux and macOS (including ARM64).
- **Audit Logging**: Maintains a persistent `JSONL` history of all network activities.
- **Developer Friendly**: Modular architecture designed for easy extension and community contributions.

---

## 📂 Project Structure

```
├── src/
│   ├── injector.py      <-- Core network logic (Raw socket assembly)
│   ├── server.py        <-- WebSocket API & Command Dispatcher
│   └── __init__.py      <-- Package exports
├── logs/
│   └── netdev_server.log <-- System logs
├── ICD.md               <-- Interface Control Document (Protocol definition)
├── main.py              <-- Primary application entry point
└── README.md            <-- This documentation
```

---

## 🛠️ Getting Started

### Option 1: Download Pre-compiled Binary (Easiest)
1. Go to the [Releases](https://github.com/rathilabs/netdev-backend/releases) page.
2. Download the binary for your OS (Linux/macOS).
3. Run with root privileges:
   ```bash
   sudo ./netdev-server
   ```

### Option 2: Run from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/rathilabs/netdev-backend.git
   cd netdev-backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run with root privileges:
   ```bash
   sudo python3 main.py
   ```

---

## 📂 Project Structure

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started, our coding standards, and the pull request process.

## 📄 Interface Control Document
For detailed information on the WebSocket API and message structures, refer to [ICD.md](ICD.md).

---

*Part of the NetDevs Pro Suite.*
