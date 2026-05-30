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

### Prerequisites
- Python 3.10+
- `pip`

### Installation
```bash
git clone https://github.com/rathilabs/netdev-backend.git
cd netdev-backend
pip install -r requirements.txt
```

### Running the Server
Raw sockets require **Root/Administrator** privileges.

**Linux / macOS:**
```bash
sudo python3 main.py
```

**Windows (Admin PowerShell):**
```bash
python main.py
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started, our coding standards, and the pull request process.

## 📄 Interface Control Document
For detailed information on the WebSocket API and message structures, refer to [ICD.md](ICD.md).

---

*Part of the NetDevs Pro Suite.*
