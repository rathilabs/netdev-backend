import asyncio
import json
import websockets
import os
import datetime
import logging
from logging.handlers import RotatingFileHandler
from injector import PacketInjector

# Configure Logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "server.log")

# Clear existing handlers if any
root_logger = logging.getLogger()
if root_logger.hasHandlers():
    root_logger.handlers.clear()

root_logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')

# File Handler
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
file_handler.setFormatter(formatter)
root_logger.addHandler(file_handler)

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

logger = logging.getLogger("PacketServer")
logger.info("--- Logging System Initialized ---")

class PacketServer:
    def __init__(self, host="0.0.0.0", port=8001):
        self.host = host
        self.port = port
        self.injector = PacketInjector()
        self.history_file = os.path.join(LOG_DIR, "packet_history.jsonl")
        
        logger.info(f"Initializing PacketServer on {host}:{port}")
        logger.info(f"Packet history stored in: {self.history_file}")

    def save_history(self, config, status, message):
        """
        Saves packet transaction to a JSONL file for the UI history.
        """
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "config": config,
            "status": status,
            "message": message
        }
        try:
            with open(self.history_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            logger.debug(f"History entry saved: {status}")
        except Exception as e:
            logger.error(f"Failed to save history entry: {e}")

    async def handle_client(self, websocket):
        """
        Handles incoming WebSocket messages following the ICD.
        """
        remote_addr = getattr(websocket, 'remote_address', 'Unknown')
        logger.info(f"Client connected from {remote_addr}")
        
        try:
            async for message in websocket:
                logger.debug(f"Received raw message: {message[:200]}{'...' if len(message) > 200 else ''}")
                try:
                    data = json.loads(message)
                    command = data.get("command")
                    logger.info(f"Processing command: {command} from {remote_addr}")
                    
                    response = None

                    if command == "SEND_PACKET":
                        payload_config = data.get("config", {})
                        logger.debug(f"Packet configuration: {json.dumps(payload_config)}")
                        
                        success, detail = self.injector.send_packet(payload_config)
                        
                        # Persist to history
                        self.save_history(payload_config, "SUCCESS" if success else "ERROR", detail)
                        
                        status = "SUCCESS" if success else "ERROR"
                        logger.info(f"Packet injection result: {status} - {detail}")
                        
                        response = {
                            "status": status,
                            "message": detail,
                            "original_command": "SEND_PACKET"
                        }
                        
                    elif command == "FETCH_LOGS":
                        logger.debug("Fetching history logs...")
                        logs = []
                        if os.path.exists(self.history_file):
                            with open(self.history_file, "r") as f:
                                # Return last 500 logs to prevent overflow
                                lines = f.readlines()
                                logs = [json.loads(line) for line in lines[-500:]]
                        
                        logger.info(f"Returning {len(logs)} history entries to {remote_addr}")
                        response = {
                            "status": "SUCCESS",
                            "command": "FETCH_LOGS",
                            "data": logs[::-1] # Newest first
                        }

                    elif command == "CLEAR_LOGS":
                        logger.warning(f"Client {remote_addr} requested clearing logs")
                        if os.path.exists(self.history_file):
                            os.remove(self.history_file)
                        response = {
                            "status": "SUCCESS",
                            "message": "Persistent history cleared"
                        }
                        
                    elif command == "PING":
                        logger.debug(f"Received PING from {remote_addr}")
                        response = {"status": "PONG"}
                        
                    else:
                        logger.error(f"Unknown command received: {command}")
                        response = {
                            "status": "ERROR",
                            "message": f"Unknown command: {command}"
                        }

                    if response:
                        resp_json = json.dumps(response)
                        logger.debug(f"Sending response: {resp_json[:200]}{'...' if len(resp_json) > 200 else ''}")
                        await websocket.send(resp_json)
                        
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON received from {remote_addr}")
                    await websocket.send(json.dumps({
                        "status": "ERROR",
                        "message": "Invalid JSON format"
                    }))
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client disconnected: {remote_addr}")
        except Exception as e:
            logger.exception(f"Unexpected error handling client {remote_addr}: {e}")

    async def start(self):
        async with websockets.serve(self.handle_client, self.host, self.port):
            logger.info(f"WebSocket Server running on ws://{self.host}:{self.port}")
            await asyncio.Future()  # run forever

if __name__ == "__main__":
    server = PacketServer()
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Server stopping due to KeyboardInterrupt...")
    except Exception as e:
        logger.critical(f"Server crashed: {e}", exc_info=True)
