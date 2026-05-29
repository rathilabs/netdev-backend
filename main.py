import asyncio
import logging
import sys
import os
from src import PacketServer
from logging.handlers import RotatingFileHandler

def setup_logging():
    """Configures a professional rotating log system for the backend."""
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_file = os.path.join(log_dir, "netdev_server.log")
    
    # Root Logger Configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    # File Handler (5MB per file, max 5 backups)
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

async def main():
    """Main application entry point."""
    setup_logging()
    logger = logging.getLogger("NetDev.Main")
    
    logger.info("--- NetDev Pro Backend Engine Starting ---")
    
    server = PacketServer(host="0.0.0.0", port=8001)
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received (Ctrl+C).")
    except Exception as e:
        logger.critical(f"Engine failure: {e}", exc_info=True)
    finally:
        logger.info("--- NetDev Pro Backend Engine Stopped ---")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass # Silent exit on Ctrl+C
