# 🛡️ Simple EDR Agent (Python + Tkinter GUI)

A lightweight **Endpoint Detection and Response (EDR)** agent built with Python and Tkinter. It monitors process activity, file system changes, and network connections in real-time and displays alerts through an intuitive graphical user interface.

---

## 📸 Screenshot

![Screenshot 2025-06-11 121249](https://github.com/user-attachments/assets/05f06dd8-f5b4-4312-bcf8-58c5f140b429)


---

## 🔍 Features

✅ **Real-time GUI Dashboard**
✅ **Process Monitoring** – Detects new or suspicious processes
✅ **File System Monitoring** – Detects file creation/modification
✅ **Malicious File Detection** – Hash-based detection (SHA256)
✅ **Network Connection Logging** – Logs established TCP/UDP connections
✅ **Extensible** – Easily integrate with VirusTotal, AbuseIPDB, or Slack

---

## 🧰 Requirements

* Python 3.7+
* [`psutil`](https://pypi.org/project/psutil/)
* [`watchdog`](https://pypi.org/project/watchdog/)

### 📦 Install Dependencies

```bash
pip install psutil watchdog
```

---

## 🚀 How to Run

```bash
python edr.py
```

> 🪪 Run as **Administrator (Windows)** or use `sudo` (Linux/Mac) for best results.

---

## 📂 Project Structure

```
edr.py         # Main EDR agent with Tkinter GUI
README.md          # Project documentation
```

---

## ⚠️ Known Bad Hash DB (Mock)

The script uses a small set of simulated malicious file hashes:

```python
known_bad_hashes = {
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Empty file hash
}
```

You can expand this by:

* Integrating with [VirusTotal](https://www.virustotal.com/)
* Using your organization's threat intel feed

---

## 🧪 Test Cases

* **File Events**: Create or modify files in the same directory as the script.
* **Process Events**: Open a new app (e.g., Notepad or Terminal).
* **Network Events**: Open a browser to generate traffic.

---

## ✨ Future Improvements

* Slack/email alert integration
* VirusTotal IP/URL/File scan
* Configurable watch paths
* Export reports (PDF/CSV)
