# Project 2: Network Security Port Scanner

**College Cybersecurity Assignment Prototype**  
A high-performance, multithreaded TCP port scanner with a modern cybersecurity web interface. Designed for rapid academic demonstrations (under 3 minutes) illustrating core socket programming, TCP handshake states, open/closed port detection, and input error handling.

---

## 🎯 Project Objectives & Academic Scope

- **Socket-Level Networking**: Utilizes Python's native `socket` library to execute standard TCP connect scans (`connect_ex`).
- **Concurrent Execution**: Employs `ThreadPoolExecutor` to scan dozens to hundreds of ports in sub-second intervals.
- **Port State Detection**: Accurately distinguishes between `OPEN` (SYN-ACK / connection established) and `CLOSED` (RST / connection refused / timeout).
- **Service Mapping & Latency**: Resolves well-known IANA service names and measures round-trip socket connection latency in milliseconds.
- **Robust Error Handling**: Gracefully catches DNS resolution failures, invalid IP formats, socket timeouts, and out-of-bounds port inputs.
- **Zero Bloat**: Focused strictly on academic requirements—no complex enterprise analytics, dashboards, or external threat intelligence dependencies.

---

## 📸 Screenshots

| Active Scan Results & Metrics | Input Validation & Error Handling |
| :---: | :---: |
| ![Scan Results](screenshots/01_active_scan_results.png) | ![Error Handling](screenshots/02_error_handling.png) |

---

## 🛠️ Tech Stack & Architecture

```
network security port scanner/
├── app.py                   # Flask server coordinating HTTP API & frontend
├── scanner.py               # Core multithreaded socket engine & service lookup
├── requirements.txt         # Minimal project dependencies (Flask, Pillow)
├── render_screenshots.py    # Script for generating documentation preview images
├── static/
│   ├── style.css            # Sleek cybersecurity dark-mode design system
│   └── app.js               # Reactive UI controller (timer, fetch, filters)
├── templates/
│   └── index.html           # Single-page interface (parameters, metrics, results table)
├── screenshots/             # Interface preview screenshots
└── README.md                # Documentation & 3-minute evaluation guide
```

- **Backend**: Python 3.10+ & Flask (lightweight REST API).
- **Socket Engine**: Standard Python `socket` module (`socket.AF_INET`, `socket.SOCK_STREAM`) with `concurrent.futures`.
- **Frontend**: Vanilla HTML5, modern CSS3 (glassmorphic dark cyber theme), and vanilla JavaScript.

---

## 🚀 Installation & Setup Instructions

### Prerequisites
- Python 3.10 or newer (`py` or `python` on Windows/macOS/Linux)
- `pip` package manager

### 1. Clone or Open the Project Directory
```powershell
cd "c:\Cybersecurity\network security port scanner"
```

### 2. Setup Options

#### Option A: Using a Virtual Environment (Standard / Clean Environment)
```powershell
# Create virtual environment
py -m venv venv

# Activate on Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Start scanner server
python app.py
```

#### Option B: Direct Run (Using Windows Python Launcher)
```powershell
# Install dependencies
py -m pip install -r requirements.txt

# Start scanner server
py app.py
```

### 3. Verification Confirmation
Once launched, you will see the console confirmation:
```
=======================================================
 Network Security Port Scanner Started!
 Access Web Interface at: http://127.0.0.1:5055
=======================================================
```

### 4. Open in Your Browser
Navigate to **[http://127.0.0.1:5055](http://127.0.0.1:5055)** in Google Chrome, Microsoft Edge, or Firefox.

---

## ⏱️ 3-Minute College Demonstration Guide

Follow this streamlined script during your presentation or evaluation:

### Minute 1: Introduction & Architecture (0:00 - 1:00)
1. **Explain Purpose**:
   > *"This prototype demonstrates standard TCP 3-way handshake port scanning built with a Python socket engine and a reactive dark-mode web interface."*
2. **Highlight Code Simplicity**:
   - Point out [`scanner.py`](scanner.py): standard socket `connect_ex` logic, non-blocking thread pool execution, and IANA service dictionary lookup.
   - Point out [`app.py`](app.py): clean REST endpoint `/api/scan` that accepts target IP and port parameters and returns JSON results.

### Minute 2: Demonstration of Core Port Scanning (1:00 - 2:00)
1. In the browser, leave the Target IP as `127.0.0.1` (Localhost).
2. Keep the default Port Range (`20 - 100`) or click the quick preset button **"Common (20-100)"**.
3. Click **"Execute Port Scan"**:
   - Notice the animated radar pulse and live elapsed timer.
   - The scan completes in **under 0.5 seconds**!
4. Review the **Summary Cards**:
   - **Target Resolved**: `127.0.0.1`
   - **Ports Scanned**: `81`
   - **Open Ports**: Green highlighted badge
   - **Closed Ports**: Gray/muted badge
   - **Scan Duration**: e.g., `0.34s`
5. Show the **Results Table**:
   - Point to open ports (e.g., Port `135` MS-RPC or Port `445` SMB).
   - Click the **"Open Only"** filter button to instantly filter out closed ports.
   - Use the **Search bar** to quickly find a service (e.g., type `rpc` or `http`).

### Minute 3: Error Handling & Custom Options (2:00 - 3:00)
1. **DNS & Target Validation**:
   - Change the Target IP to an invalid hostname: `invalid.domain.test999`.
   - Click **"Execute Port Scan"**.
   - Show the red alert banner: *"DNS resolution failed for 'invalid.domain.test999'. Hostname or IP is invalid or unreachable."*
2. **Port Bounds Validation**:
   - Switch back to `127.0.0.1` and enter an out-of-range port like `70000`.
   - Show the error handling: *"Port numbers must be between 1 and 65535."*
3. **Common Profiles / Custom Mode**:
   - Click the **"Common Profiles"** tab, select **"Web Stack"** or **"Top 20 Security Ports"**, and scan.
   - Conclude by stating that the scanner satisfies all prototype requirements with safety caps and zero external bloat.

---

## 🔬 Networking & Security Concepts

### 1. TCP Connect Scan Mechanics
The scanner establishes a full TCP connection using the OS socket API:
```
Scanner Client                     Target Server
      |                                  |
      | -------- SYN (Port X) ---------> |
      |                                  |
      | <------ SYN-ACK (If Open) ------ |  ==> Port marked OPEN
      |                                  |
      | <------ RST-ACK (If Closed) ---- |  ==> Port marked CLOSED
```
- When `connect_ex((ip, port))` returns `0`, the socket successfully established a connection.
- When it returns an error code (such as `WSAECONNREFUSED` / 10061 on Windows), the port is closed.

### 2. ThreadPool Concurrency
Scanning ports sequentially would take `N * timeout` seconds (e.g., 100 ports * 0.5s = 50 seconds). By dispatching concurrent worker threads with `ThreadPoolExecutor(max_workers=60)`, 100 ports are checked in **less than 0.5 seconds**.

### 3. Safe Demonstrations
- The maximum range per scan is capped at 1024 ports to ensure instantaneous responsiveness during college presentations.
- Default target is `127.0.0.1` (loopback), completely safe and compliant with academic network testing rules.

---

## 📋 Academic Assignment Compliance Checklist

- [x] **Target IP input**: Text field with hostname/IP auto-resolution & quick presets.
- [x] **Port range input**: Start & End port fields, preset chips, and custom lists.
- [x] **Port scanning**: Concurrent TCP socket scanning engine.
- [x] **Open/closed port detection**: Status badges, latency metrics, service names.
- [x] **Error handling**: DNS failure, timeout, invalid ranges, and UI error banners.
- [x] **Results display**: Metrics overview cards and responsive filtered table.
- [x] **Python backend**: Flask REST API (`app.py` & `scanner.py`).
- [x] **Simple HTML/CSS frontend**: Sleek cyber dark mode (`index.html`, `style.css`, `app.js`).
- [x] **Avoided bloat**: No threat intelligence, analytics dashboards, or enterprise reporting.
- [x] **README.md**: Full architecture, installation instructions, and 3-minute demo script.
- [x] **screenshots folder**: Captured demonstration screenshots included.
- [x] **Demonstrable in under 3 minutes**: Optimized for instant, snappy presentation.
#   n e t w o r k - s e c u r i t y - p o r t - s c a n n e r  
 