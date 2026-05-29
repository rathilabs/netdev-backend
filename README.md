# NetDevs Pro — Packet Injection Backend

The NetDevs Pro Backend is a high-performance, asynchronous Python service designed to bridge the gap between the browser-based UI and the system's network stack. It provides raw socket capabilities to inject hand-crafted Layer 3 and Layer 4 packets directly onto the local network, bypassing browser security sandboxing.

---

## 1. Overview & System Architecture

The backend operates as a standalone WebSocket server that receives structured packet definitions from the frontend, assembles them into raw binary frames, and transmits them using system-level raw sockets.

### Architectural Layout

```
      ┌──────────────────────────┐             ┌──────────────────────────┐
      │    NetDevs Pro UI        │             │   Python Injection Core  │
      │   (React Frontend)       │             │      (Backend)           │
      └──────────┬───────────────┘             └──────────┬───────────────┘
                 │                                        │
                 │         WebSocket (Port 8001)          │
                 │ ◄────────────────────────────────────► │
                 │        JSON Commands (ICD)             │
                 │                                        │
                 ▼                                        ▼
      ┌──────────────────────────┐             ┌──────────────────────────┐
      │  Packet Configuration    │             │  Raw Socket Injection    │
      │  (JSON Structure)        │             │  (Binary Serialization)  │
      └──────────────────────────┘             └──────────┬───────────────┘
                                                          │
                                                          ▼
                                               ┌──────────────────────────┐
                                               │      Network Stack       │
                                               │   (Localhost / LAN)      │
                                               └──────────────────────────┘
```

- **Asynchronous WebSocket Layer**: Handles multiple concurrent client connections using `asyncio` and `websockets`.
- **Packet Assembly Engine**: Manually constructs IPv4, TCP, and UDP headers including RFC-compliant checksum calculations.
- **Persistent Logging Layer**: Maintains a JSONL (JSON Lines) audit trail of every packet injected for later analysis in the UI.

---

## 2. Code & File Structure

The backend is designed with modularity in mind, separating the communication logic from the network-level injection logic.

```
├── logs/
│   └── packet_history.jsonl      <-- Persistent audit trail of all transactions
├── ICD.md                        <-- Interface Control Document (Protocol definition)
├── README.md                     <-- This documentation
├── injector.py                   <-- Core PacketInjector class (Raw socket logic)
└── server.py                     <-- Entry point: WebSocket server and API handlers
```

---

## 3. Module Descriptions

### ⚙️ Injection Engine (`injector.py`)
The heart of the backend. It does not rely on high-level libraries like Scapy, ensuring maximum control and transparency.
- **Manual Header Crafting**: Uses Python's `struct` library to pack bits and bytes for IP, TCP, and UDP.
- **RFC 1071 Checksum**: Implements the standard Internet Checksum algorithm to ensure packets are accepted by the target OS.
- **Raw Socket Management**: Manages `AF_INET` / `SOCK_RAW` sockets with `IP_HDRINCL` enabled.

### 🌐 WebSocket Server (`server.py`)
Manages the lifecycle of connections and translates UI requests into engine actions.
- **Command Dispatcher**: Routes commands like `SEND_PACKET`, `FETCH_LOGS`, `CLEAR_LOGS`, and `PING`.
- **JSONL Persistence**: Efficiently appends log entries to a flat file (`logs/packet_history.jsonl`) to ensure an audit trail survives server restarts.

### 📄 Interface Control Document (`ICD.md`)
Defines the contract between the frontend and backend. It specifies the JSON schema for every supported command, making it easy to extend the system with new protocols (e.g., ICMP, ARP) or new fields.

---

## 4. Execution Flow

1. **Initialization**: The server boots and attempts to open a raw socket. 
   - *Note: This requires Root/Administrator privileges.*
2. **UI Handshake**: The React frontend connects via `ws://127.0.0.1:8001`.
3. **Command Loop**:
   - UI sends `SEND_PACKET` with header details.
   - `server.py` passes config to `injector.py`.
   - `injector.py` builds the binary frame and calls `socket.sendto()`.
   - Result is logged to `logs/packet_history.jsonl`.
   - Success/Error status is returned to the UI.
4. **Log Analysis**: UI sends `FETCH_LOGS`, and the server streams the last 500 entries of the history file back to the browser.
5. **Maintenance**: UI sends `CLEAR_LOGS` to wipe the persistent history file.
6. **Health Check**: UI sends `PING` to receive a `PONG` response.

---

## 5. Setup & Local Execution

### Prerequisites
- Python 3.10+
- `websockets` library

### Step 1: Install Dependencies
```bash
pip install websockets
```

### Step 2: Run with Privileges
Raw sockets are a restricted system operation.

**Linux / macOS:**
```bash
sudo python3 backend/server.py
```

**Windows:**
1. Open PowerShell/CMD as **Administrator**.
2. Run:
```bash
python backend/server.py
```

---

## 6. Testing & Verification

The backend includes self-checks for common issues:
- **Permission Check**: Will warn if run without root/admin privileges.
- **Syntax Check**: All modules use strict type-hinting and modular classes.
- **Ping/Pong**: Use the `PING` command via any WebSocket client to verify server health.
