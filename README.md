# Windows Privilege Escalation & Reverse Shell PoC

> **Disclaimer:** This repository contains documentation and analysis of a custom Proof of Concept (PoC) tool developed for educational purposes and security research. The full source code is intentionally omitted to prevent misuse. This project demonstrates understanding of Windows Internals, WinAPI interaction, and low-level socket programming.

## 📌 Project Overview
This project is a custom implementation of a **Reverse Shell** written in **C/C++**, featuring built-in **Privilege Escalation** capabilities. The tool is designed to bypass standard user limitations by manipulating Windows Access Tokens, effectively elevating the payload execution context from a standard user to `NT AUTHORITY\SYSTEM`.

The primary goal of this research was to explore:
* **Windows API & Handle Manipulation**
* **Token Impersonation & Duplication** (`Advapi32.lib`)
* **Manual Socket Management** (`Ws2_32.lib`)
* **Process Injection Techniques**

## ⚙️ Key Features

### 1. Dual-Mode Architecture
To maintain operational security (OpSec), the code allows for two compilation modes defined by preprocessor directives:
* **Generator Mode (`BUILD_MODE 0`):** A utility helper that encrypts configuration strings (IP/Port) locally.
* **Attack Mode (`BUILD_MODE 1`):** The final payload that contains only the obfuscated strings and the execution logic.

### 2. String Obfuscation (XOR)
To evade static analysis and basic signature detection, all sensitive strings (C2 IP address and Port) are encrypted at rest.
* **Algorithm:** Custom XOR implementation.
* **Runtime Behavior:** Strings are decrypted in memory only at the moment they are needed for the connection, and then wiped.

### 3. Automatic Privilege Escalation (Token Theft)
The tool identifies high-privilege processes and attempts to steal their token to spawn a new shell as SYSTEM.
* **Target:** `winlogon.exe` (System integrity process).
* **Technique:**
    1.  Enables `SeDebugPrivilege` to interact with system processes.
    2.  Enumerates running processes via `CreateToolhelp32Snapshot`.
    3.  Opens the target process and duplicates its Primary Token (`DuplicateTokenEx`).
    4.  Spawns the reverse shell using `CreateProcessWithTokenW`.

---

## 🔧 Execution Flow (Diagram)

The following diagram illustrates the internal logic of the tool when executed on a target machine:

```mermaid
graph TD
    A[Start Execution] --> B{Check Current User}
    B -- Already SYSTEM --> F[Decrypt Config & Connect]
    B -- Normal User --> C[Enable SeDebugPrivilege]
    C --> D[Find 'winlogon.exe' PID]
    D --> E[Duplicate Primary Token]
    E --> G[Relaunch with SYSTEM Token]
    G --> F
    F --> H[Spawn cmd.exe via Pipes]
    H --> I[Establish C2 Connection]
