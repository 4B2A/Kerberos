# Kerberos 🐉

**Kerberos** is an automated, lightweight binary crash and exploitability analyzer written in Python. It acts as an intelligent dynamic triaging assistant designed to automatically fuzz locally compiled binaries, monitor execution behavior under GDB, detect dynamic entry methods, and score vulnerability impact.

## 🌟 Key Features

*   **Auto-Input Detection:** Smartly assesses whether the target application expects data via standard input (`STDIN`) or command-line arguments (`ARGV`).
*   **Dynamic Monitoring:** Spawns an isolated `GDB` instance in the background to catch precise signals (`SIGSEGV`, `SIGBUS`, `SIGILL`) and register dumps.
*   **Cyclic Offset Engineering:** Utilizes `pwntools` unique pattern generation to precisely isolate the buffer overflow crash byte index.
*   **Vulnerability Scoring:** Features a lightweight risk classification logic based on target binary mitigations (**NX**, **PIE**, **Architecture**) combined with control register alignment.

## 🚀 Installation & Usage

### 1. Install System Dependencies
Ensure you have `gdb` installed on your Linux environment:
```bash
sudo apt update && sudo apt install gdb python3-pip -y
```

### 2. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 3. Execution
Launch the dynamic interface seamlessly via terminal:
```bash
python3 kerberos.py
```

---

## ⚠️ Disclaimer

**IMPORTANT:** This software is provided for educational, research, and authorized security assessment purposes only. The author (`4B2A`) assumes no liability for malicious actions, misuse, or damage caused by this utility. Always secure proper explicit authorization before auditing binaries or networks.
