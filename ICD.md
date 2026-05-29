# Interface Control Document (ICD) - PacketStreamer

## 1. Overview
This document defines the communication protocol between the NetDevs Pro Frontend (React/TypeScript) and the Python Packet Injection Backend.

## 2. Communication Channel
- **Protocol**: WebSocket
- **Default URL**: `ws://127.0.0.1:8001`
- **Serialization**: JSON
- **Backend Implementation**: `backend/server.py`
- **Frontend Implementation**: `website/src/components/PacketCrafter.tsx`, `website/src/components/LogAnalyzer.tsx`

---

## 3. Communication Flow
1. **Connection**: Frontend initiates a WebSocket connection to the backend.
2. **Command**: Frontend sends a JSON command object.
3. **Execution**: Backend processes the command (e.g., injects packet, reads logs).
4. **Persistence**: For `SEND_PACKET` commands, the backend logs the transaction to `backend/logs/packet_history.jsonl`.
5. **Response**: Backend sends a JSON response object back to the frontend.
6. **Update**: Frontend updates its state/UI based on the response.

---

## 4. Message Structure (Frontend to Backend)

### 4.1 `SEND_PACKET`
Sent to inject a raw network packet.

**Structure**:
```json
{
  "command": "SEND_PACKET",
  "config": {
    "protocol": "TCP" | "UDP" | "ICMP",
    "srcIp": "string (IPv4)",
    "dstIp": "string (IPv4)",
    "srcPort": number,
    "dstPort": number,
    "payload": "string",
    "payloadHex": "string (optional hex representation)",
    "flags": {
      "syn": 0 | 1,
      "ack": 0 | 1,
      "fin": 0 | 1,
      "rst": 0 | 1,
      "psh": 0 | 1,
      "urg": 0 | 1
    }
  }
}
```

### 4.2 `FETCH_LOGS`
Retrieves the last 500 entries from the persistent history file.

**Structure**:
```json
{
  "command": "FETCH_LOGS"
}
```

### 4.3 `CLEAR_LOGS`
Wipes the persistent history file on the backend.

**Structure**:
```json
{
  "command": "CLEAR_LOGS"
}
```

### 4.4 `PING`
Heartbeat check.

**Structure**:
```json
{
  "command": "PING"
}
```

---

## 5. Message Structure (Backend to Frontend)

### 5.1 General Response
Sent for `SEND_PACKET`, `CLEAR_LOGS`, and unknown commands.

**Structure**:
```json
{
  "status": "SUCCESS" | "ERROR",
  "message": "Human readable detail or error message",
  "original_command": "The command this response is for"
}
```

### 5.2 `FETCH_LOGS` Response
Returns an array of log entries.

**Structure**:
```json
{
  "status": "SUCCESS",
  "command": "FETCH_LOGS",
  "data": [
    {
      "timestamp": "ISO-8601 string",
      "config": { ...original_config... },
      "status": "SUCCESS" | "ERROR",
      "message": "Detail message"
    }
  ]
}
```

### 5.3 `PING` Response (`PONG`)
**Structure**:
```json
{
  "status": "PONG"
}
```

### 5.4 Error Response
Sent when invalid JSON is received.

**Structure**:
```json
{
  "status": "ERROR",
  "message": "Invalid JSON format"
}
```
