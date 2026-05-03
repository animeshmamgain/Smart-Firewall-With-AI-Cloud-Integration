import sys
from datetime import datetime

class _SimpleLogger:
    def __init__(self, name):
        self.name = name
    def _log(self, level, msg):
        print(f"{datetime.now().strftime('%H:%M:%S')}  {level:8s}  {self.name:20s}  {msg}", flush=True)
    def info(self, msg):    self._log("INFO",    msg)
    def warning(self, msg): self._log("WARNING", msg)
    def error(self, msg):   self._log("ERROR",   msg)
    def debug(self, msg):   pass

def get_logger(name):
    return _SimpleLogger(f"sfw.{name}")
