import os
import logging

logger = logging.getLogger("NetworkTools.Utils")

def get_log_dir() -> str:
    """
    Determines and returns the appropriate log directory.
    Attempts local 'logs' first, falling back to '/tmp/networktools-logs' 
    for single-binary or read-only environments.
    """
    # Attempt local logs directory relative to the project root
    # We use a path relative to this file's parent's parent to reach root
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(base_dir, "logs")
    
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        return log_dir
    except OSError:
        # Fallback for single binary or read-only environments
        log_dir = "/tmp/nettools-logs"
        try:
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            return log_dir
        except OSError:
            # Last resort: current working directory
            log_dir = os.path.join(os.getcwd(), "logs")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            return log_dir
