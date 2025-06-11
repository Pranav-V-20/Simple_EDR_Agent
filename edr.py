import psutil
import time
import threading
import hashlib
import logging
import tkinter as tk
from tkinter import scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === Configure Logging ===
logging.basicConfig(
    filename="edr_gui_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# === Known Bad Hashes (Simulated Threat DB) ===
known_bad_hashes = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty file
}

# === GUI Application ===
class EDRApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple EDR Agent")
        self.root.geometry("800x500")

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
        self.output.pack(expand=True, fill='both')

        self.write_log("✅ EDR GUI Agent Started\n")

        # Setup watchdog observer
        self.observer = Observer()
        self.file_handler = FileMonitor(self)
        self.observer.schedule(self.file_handler, ".", recursive=True)
        self.observer.start()

        # Initialize known processes
        self.known_pids = set(p.pid for p in psutil.process_iter())

        # Start background monitoring
        threading.Thread(target=self.monitor_loop, daemon=True).start()

    def write_log(self, message):
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)
        logging.info(message)

    def monitor_loop(self):
        while True:
            self.monitor_processes()
            self.monitor_network()
            time.sleep(5)

    def monitor_processes(self):
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            name = proc.info['name']
            if pid not in self.known_pids:
                msg = f"🔍 New Process: {name} (PID: {pid})"
                self.write_log(msg)
                self.known_pids.add(pid)

    def monitor_network(self):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    msg = f"🌐 Network: {conn.laddr.ip}:{conn.laddr.port} → {conn.raddr.ip}:{conn.raddr.port}"
                    self.write_log(msg)
        except Exception as e:
            self.write_log(f"⚠️ Network error: {e}")

class FileMonitor(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app

    def on_created(self, event):
        if not event.is_directory:
            self.app.write_log(f"📁 File Created: {event.src_path}")
            self.check_hash(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.app.write_log(f"✏️ File Modified: {event.src_path}")
            self.check_hash(event.src_path)

    def check_hash(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                if sha256 in known_bad_hashes:
                    self.app.write_log(f"🚨 Malicious File Detected: {filepath} [SHA256: {sha256}]")
        except Exception as e:
            self.app.write_log(f"⚠️ Error reading {filepath}: {e}")

# === Start GUI ===
if __name__ == "__main__":
    root = tk.Tk()
    app = EDRApp(root)
    root.mainloop()
