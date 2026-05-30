import asyncio
import logging
import sys
import os
import datetime
from src import PacketServer
from logging.handlers import TimedRotatingFileHandler

def setup_logging():
    """Configures a professional rotating log system for the backend."""
    # Attempt to use local logs directory
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    except OSError:
        # Fallback for single binary or read-only environments
        log_dir = "/tmp/nettools-logs"
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError:
                # Last resort: current working directory
                log_dir = os.path.join(os.getcwd(), "logs")
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)

    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"server_{date_str}.log")
    ...

    # Root Logger Configuration
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))
    
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    # File Handler (Rotate every day at midnight)
    file_handler = TimedRotatingFileHandler(
        log_file, 
        when="midnight", 
        interval=1, 
        backupCount=30
    )
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
    
    logger.info("Engine starting...")
    logger.debug("Debug mode active.")
    
    server = PacketServer(host="0.0.0.0", port=8001)
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received.")
    except Exception as e:
        logger.critical(f"Engine failure: {e}", exc_info=True)
    finally:
        logger.info("Engine stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass # Silent exit on Ctrl+C
