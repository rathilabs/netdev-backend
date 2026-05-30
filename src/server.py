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
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8001, log_dir: Optional[str] = None):
        self.host = host
        self.port = port
        self.injector = PacketInjector()
        
        # Determine logs directory (default to root-level logs)
        if log_dir is None:
            self.log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        else:
            self.log_dir = log_dir
            
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        logger.info(f"Server listening on {host}:{port}")
        logger.info(f"Log directory: {self.log_dir}")

    def get_current_history_file(self) -> str:
        """Returns the history file path for the current date."""
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"history_{date_str}.jsonl")

    def save_history(self, config: dict, status: str, message: str) -> None:
        """Persists a packet injection event to a JSONL audit trail file."""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "config": config,
            "status": status,
            "message": message
        }
        try:
            history_file = self.get_current_history_file()
            with open(history_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            logger.debug(f"History saved: {status}")
        except Exception as e:
            logger.error(f"Audit log error: {e}")

    async def handle_client(self, websocket) -> None:
        """Main connection handler managing incoming WebSocket request streams."""
        remote_addr = getattr(websocket, 'remote_address', 'Unknown')
        logger.debug(f"Session started: {remote_addr}")
        
        try:
            async for raw_message in websocket:
                logger.debug(f"Data received from {remote_addr}")
                try:
                    data = json.loads(raw_message)
                    command = data.get("command")
                    logger.debug(f"Command '{command}' from {remote_addr}")
                    
                    response = await self.dispatch_command(command, data, remote_addr)
                    
                    if response:
                        await websocket.send(json.dumps(response))
                        
                except json.JSONDecodeError:
                    logger.error(f"JSON error from {remote_addr}")
                    await websocket.send(json.dumps({
                        "status": "ERROR",
                        "message": "Invalid JSON format"
                    }))
        except websockets.exceptions.ConnectionClosed:
            logger.debug(f"Session closed: {remote_addr}")
        except Exception as e:
            logger.exception(f"Handler error ({remote_addr}): {e}")

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
            history_file = self.get_current_history_file()
            logs = []
            if os.path.exists(history_file):
                with open(history_file, "r") as f:
                    lines = f.readlines()
                    # Return last 500 logs to prevent payload overflow
                    logs = [json.loads(line) for line in lines[-500:]]
            
            return {
                "status": "SUCCESS",
                "command": "FETCH_LOGS",
                "data": logs[::-1] # Sort newest first
            }

        elif command == "LIST_LOGS":
            files = []
            for f in os.listdir(self.log_dir):
                path = os.path.join(self.log_dir, f)
                if os.path.isfile(path):
                    stats = os.stat(path)
                    files.append({
                        "name": f,
                        "size": stats.st_size,
                        "modified": datetime.datetime.fromtimestamp(stats.st_mtime).isoformat()
                    })
            # Sort by modified date recent first
            files.sort(key=lambda x: x["modified"], reverse=True)
            return {
                "status": "SUCCESS",
                "command": "LIST_LOGS",
                "data": files
            }

        elif command == "READ_LOG":
            filename = data.get("filename")
            if not filename:
                return {"status": "ERROR", "message": "Filename missing"}
            
            # Basic security check to prevent path traversal
            if ".." in filename or "/" in filename or "\\" in filename:
                return {"status": "ERROR", "message": "Invalid filename"}
            
            path = os.path.join(self.log_dir, filename)
            if not os.path.exists(path):
                return {"status": "ERROR", "message": "File not found"}
            
            try:
                with open(path, "r") as f:
                    # Return content (could be large, but usually okay for logs)
                    content = f.read()
                    return {
                        "status": "SUCCESS",
                        "command": "READ_LOG",
                        "filename": filename,
                        "data": content
                    }
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        elif command == "DELETE_LOG":
            filename = data.get("filename")
            if not filename:
                return {"status": "ERROR", "message": "Filename missing"}
            
            if ".." in filename or "/" in filename or "\\" in filename:
                return {"status": "ERROR", "message": "Invalid filename"}
            
            path = os.path.join(self.log_dir, filename)
            if not os.path.exists(path):
                return {"status": "ERROR", "message": "File not found"}
            
            try:
                os.remove(path)
                logger.info(f"Log file {filename} deleted by {remote_addr}")
                return {
                    "status": "SUCCESS",
                    "command": "DELETE_LOG",
                    "message": f"File {filename} deleted successfully."
                }
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        elif command == "CLEAR_LOGS":
            logger.warning(f"Full log wipe requested by {remote_addr}")
            count = 0
            for f in os.listdir(self.log_dir):
                path = os.path.join(self.log_dir, f)
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                        count += 1
                except Exception as e:
                    logger.error(f"Failed to delete {f}: {e}")
            return {
                "status": "SUCCESS",
                "message": f"All {count} log files deleted successfully."
            }
            
        elif command == "PING":
            return {"status": "PONG"}
            
        else:
            logger.error(f"Unknown command: {command}")
            return {
                "status": "ERROR",
                "message": f"Unknown command scope: {command}"
            }

    async def start(self) -> None:
        """Starts the WebSocket event loop engine."""
        async with websockets.serve(self.handle_client, self.host, self.port):
            logger.info(f"WebSocket live at ws://{self.host}:{self.port}")
            await asyncio.Future() # Keep running indefinitely
