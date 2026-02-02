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

### 4. Custom I/O Pipe Handling
Instead of using standard library calls, the shell interaction is managed via Windows Pipes.
* Standard Input/Output/Error (STDIN/STDOUT/STDERR) are redirected through anonymous pipes.
* A dedicated loop forwards data between the Winsock socket and the `cmd.exe` process pipes.

---

## 🔧 Technical Deep Dive

### The Execution Flow

Below is the logical flow of the payload execution:

1.  **Initialization:** The payload starts and decrypts its configuration.
2.  **Privilege Check:** It calls a custom `IsSystem()` function to check the current user context.
    * *If `SYSTEM`:* Proceed directly to payload execution.
    * *If `User`:* Initiate Escalation Routine.
3.  **Escalation Routine:**
    * The tool hunts for the PID of `winlogon.exe`.
    * It acquires a handle with `TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`.
    * It relaunches itself (or the payload logic) using the stolen token.
4.  **Connection:** Finally, it establishes a TCP connection to the C2 server and spawns `cmd.exe` (hidden window).

### Code Snippet: Token Manipulation Logic
*A snippet demonstrating the logic used for token duplication (Sanitized for display):*

```c
// Enabling necessary privileges for token manipulation
EnablePrivilege(SE_DEBUG_NAME);
EnablePrivilege(SE_IMPERSONATE_NAME);

// ... Finding target process logic ...

// Duplicating the token to create a Primary Token for new process creation
if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken)) {
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDup);
    // hDup is now a valid SYSTEM token ready for CreateProcessWithTokenW
}
