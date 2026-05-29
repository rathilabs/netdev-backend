import asyncio
import json
import websockets
import os
import datetime
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, Any
from .injector import PacketInjector

logger = logging.getLogger("NetDev.Server")

class PacketServer:
    """
    Asynchronous WebSocket server that processes incoming client connections,
    dispatches commands following the Interface Control Document (ICD),
    and communicates with the underlying PacketInjector engine.
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8001, log_dir: Optional[str] = None):
        self.host = host
        self.port = port
        self.injector = PacketInjector()
        
        # Determine logs directory (default to root-level logs)
        if log_dir is None:
            log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
            
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        self.history_file = os.path.join(log_dir, "packet_history.jsonl")
        logger.info(f"PacketServer initialized. Listening on {host}:{port}")
        logger.info(f"Audit log history stored in: {self.history_file}")

    def save_history(self, config: dict, status: str, message: str) -> None:
        """Persists a packet injection event to a JSONL audit trail file."""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "config": config,
            "status": status,
            "message": message
        }
        try:
            with open(self.history_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            logger.debug(f"History entry recorded with status: {status}")
        except Exception as e:
            logger.error(f"Failed to append to history log: {e}")

    async def handle_client(self, websocket) -> None:
        """Main connection handler managing incoming WebSocket request streams."""
        remote_addr = getattr(websocket, 'remote_address', 'Unknown')
        logger.info(f"Client session initiated from {remote_addr}")
        
        try:
            async for raw_message in websocket:
                logger.debug(f"Received data block: {raw_message[:200]}")
                try:
                    data = json.loads(raw_message)
                    command = data.get("command")
                    logger.info(f"Processing command '{command}' from {remote_addr}")
                    
                    response = await self.dispatch_command(command, data, remote_addr)
                    
                    if response:
                        await websocket.send(json.dumps(response))
                        
                except json.JSONDecodeError:
                    logger.error(f"Malformed JSON received from {remote_addr}")
                    await websocket.send(json.dumps({
                        "status": "ERROR",
                        "message": "Invalid JSON format"
                    }))
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client session closed: {remote_addr}")
        except Exception as e:
            logger.exception(f"Unexpected error handling client {remote_addr}: {e}")

    async def dispatch_command(self, command: str, data: dict, remote_addr: Any) -> Optional[dict]:
        """
        Routes the command to its respective business logic handler.
        Contributors can easily add new commands by extending this block.
        """
        if command == "SEND_PACKET":
            payload_config = data.get("config", {})
            success, detail = self.injector.send_packet(payload_config)
            
            status = "SUCCESS" if success else "ERROR"
            self.save_history(payload_config, status, detail)
            
            return {
                "status": status,
                "message": detail,
                "original_command": "SEND_PACKET"
            }
            
        elif command == "FETCH_LOGS":
            logs = []
            if os.path.exists(self.history_file):
                with open(self.history_file, "r") as f:
                    lines = f.readlines()
                    # Return last 500 logs to prevent payload overflow
                    logs = [json.loads(line) for line in lines[-500:]]
            
            return {
                "status": "SUCCESS",
                "command": "FETCH_LOGS",
                "data": logs[::-1] # Sort newest first
            }

        elif command == "CLEAR_LOGS":
            logger.warning(f"Client {remote_addr} triggered persistent log deletion.")
            if os.path.exists(self.history_file):
                os.remove(self.history_file)
            return {
                "status": "SUCCESS",
                "message": "Persistent history wiped successfully."
            }
            
        elif command == "PING":
            return {"status": "PONG"}
            
        else:
            logger.error(f"Unrecognized command context received: {command}")
            return {
                "status": "ERROR",
                "message": f"Unknown command scope: {command}"
            }

    async def start(self) -> None:
        """Starts the WebSocket event loop engine."""
        async with websockets.serve(self.handle_client, self.host, self.port):
            logger.info(f"WebSocket engine running live at ws://{self.host}:{self.port}")
            await asyncio.Future() # Keep running indefinitely
