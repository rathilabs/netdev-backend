import os
import logging
import sys

logger = logging.getLogger("NetworkTools.Utils")

def get_log_dir() -> str:
    """
    Determines and returns the appropriate log directory.
    Attempts local 'logs' next to executable/source first, 
    falling back to a persistent temp dir for single-binary or read-only environments.
    """
    if getattr(sys, 'frozen', False):
        # Running as a bundle (PyInstaller/nuitka)
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running as a normal python script
        # We use a path relative to this file's parent's parent to reach root
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    log_dir = os.path.join(base_dir, "logs")
    
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        return log_dir
    except OSError:
        # Fallback for single binary or read-only environments
        log_dir = "/tmp/networktools-logs"
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
