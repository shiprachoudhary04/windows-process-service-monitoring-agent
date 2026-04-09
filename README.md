# 🛡️ Windows Service & Process Monitoring Agent

A real-time Windows monitoring agent designed to detect suspicious processes, abnormal parent-child relationships, unauthorized executions, and potential security threats.

This project simulates a lightweight **Endpoint Detection & Response (EDR)** system using Python.

---

## 🚀 Features

* 🔄 Real-time process monitoring
* 🧬 Parent-child process analysis
* ⚠️ Unauthorized process detection (Whitelist-based)
* 📁 Suspicious execution path detection (Temp/AppData)
* 🔐 File hash generation (SHA-256)
* 📊 JSON-based structured logging
* 🚨 Alert system with severity levels (HIGH / MEDIUM)
* 🛑 Graceful shutdown support
* 🔍 Windows service monitoring *(local environment only)*

---

## 🧠 How It Works

1. Enumerates all active processes using `psutil`
2. Builds parent-child relationships using PID & PPID
3. Applies rule-based detection logic
4. Flags suspicious behavior:

   * winword → powershell
   * browser → cmd
   * execution from Temp/AppData
5. Generates alerts with severity levels
6. Logs all events in structured JSON format
7. Continuously monitors system in real-time

---

## 🏗️ Project Structure

```
📁 windows-process-service-monitoring-agent
│
├── monitor_final.py        # Main monitoring script
├── whitelist.txt           # Allowed processes
├── monitor_log.json        # Generated logs
├── requirements.txt        # Dependencies
└── README.md               # Project documentation
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/windows-process-service-monitoring-agent.git
cd windows-process-service-monitoring-agent
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Project

```bash
python monitor_final.py
```

---

## 🌐 Deployment (Streamlit)

This project is deployed using Streamlit Cloud.

⚠️ Note:

* Service monitoring works only on Windows
* Streamlit version runs process monitoring only

---

## 📊 Sample Output

```
🚨 HIGH: Suspicious Chain: winword.exe → powershell.exe
⚠ MEDIUM: Unknown Process: abc.exe
🚨 HIGH: Suspicious Location: C:\Users\AppData\Temp\xyz.exe
```

---

## 📄 Log Format (JSON)

```json
{
  "timestamp": "2026-04-09",
  "level": "HIGH",
  "process": "powershell.exe",
  "path": "C:\\Temp\\abc.exe",
  "message": "Suspicious activity detected"
}
```

---

## 🛠️ Technologies Used

* Python
* psutil
* hashlib
* JSON
* Streamlit (for deployment)

---

## ⚠️ Limitations

* Service monitoring not supported on Streamlit Cloud
* No digital signature verification
* Rule-based detection only

---

## 🔮 Future Enhancements

* Email/Telegram alert system
* SIEM integration
* Dashboard visualization
* Machine learning-based detection
* Digital signature validation

---

## 🎯 Learning Outcomes

* Windows process architecture
* Cybersecurity monitoring techniques
* Real-time system analysis
* Rule-based threat detection
* Logging & reporting systems

---

## 👩‍💻 Author

**Shipra Choudhary**

---

## ⭐ Acknowledgment

This project is developed as part of a cybersecurity-focused academic and practical learning initiative.

---

