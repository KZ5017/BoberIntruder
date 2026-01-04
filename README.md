# Custom Turbo Intruder Attack Script

This project is a highly flexible and extensible **Custom Turbo Intruder Attack Script** designed to emulate and extend Burp Suite Intruder’s attack modes, while providing advanced payload transformation, response evaluation, recursion, and attack orchestration.

The script is intentionally **dynamic and user-modifiable**, optimized for real-world testing scenarios where payload structure, count, and behavior must be adjusted quickly with minimal code changes.

---

## ✨ Key Features

- Multiple Intruder-style attack modes:
  - **Default**
  - **Sniper**
  - **Battering Ram**
  - **Pitchfork**
  - **Cluster Bomb**
- Pluggable **payload transformation pipeline**
- Centralized **response evaluation rules**
- **Recursive discovery mode** with optional expansion
- Redirect following with loop prevention
- Designed for **readability, flexibility, and on-the-fly customization**

---

## 🧠 Design Philosophy

This framework prioritizes:

- **Configurability over compactness**
- **Explicit logic over clever abstractions**
- **Safe, immutable request handling**
- Easy adaptation during live testing

The goal is to allow the user to change:
- the number of payload markers,
- payload sources,
- attack behavior,
- or recursion logic

**without rewriting large parts of the script.**

---

## 🚀 Attack Modes

### 1. Default
Single payload marker.
Each payload is tested independently.

**Equivalent to:** Intruder → Sniper (single marker)

---

### 2. Sniper
Multiple payload markers.
Each position is tested individually while others keep default placeholders.

**Use case:** Discover which parameter is injectable.

---

### 3. Battering Ram
Multiple payload markers.
The same payload is injected into **all positions simultaneously**.

**Use case:** When parameters must match or mirror each other.

---

### 4. Pitchfork
Multiple payload markers.
Payloads are tested **in parallel**, one from each payload set.

**Use case:** Username/password or paired inputs.

---

### 5. Cluster Bomb
Multiple payload markers.
Every possible payload combination is tested.

**Use case:** Exhaustive brute-force scenarios.

⚠️ Use with caution — this grows exponentially.

---

## 🔄 Payload Transformation Pipeline

Payloads can be transformed before injection using selectable modes:

- `url_enc` – URL encoding
- `extensions` – appends file extensions
- `base64` – Base64 encoding
- `custom` – fully user-defined logic
- `none` – raw payload

The transformation logic is centralized in the `transformer()` function, making it easy to extend.

---

## 🧪 Response Evaluation

All responses pass through a **rule-based evaluation engine**.

Rules are simple predicates that can:
- filter by status code
- filter by response length
- filter by word count
- match or exclude response content

This allows noisy responses to be ignored without breaking execution.

---

## 🔁 Recursive Discovery Mode

Optional recursive behavior allows the script to:

- Automatically queue follow-up requests when a directory-like response is found
- Optionally recurse even on non-trailing-slash hits
- Avoid infinite loops using exclusion lists

### Key Properties

- Recursive payloads are **preloaded once**
- Requests are generated immutably (no in-place mutation)
- Original results remain unchanged in the UI

---

## 🔀 Redirect Handling

When enabled, the script:

- Detects `Location` headers in 3xx responses
- Extracts and normalizes redirect paths
- Avoids redirect loops via exclusion rules
- Automatically queues redirected requests

---

## 🧱 Payload & Location Exclusion

Two independent exclusion mechanisms are supported:

- **Payload exclusion**  
  Prevents dangerous or unwanted payloads (e.g. `logout`)

- **Location exclusion**  
  Prevents infinite redirect loops

---

## 🛠 Configuration Overview

Key sections designed for quick modification:

- **Payload lists**
- **Default payload placeholders**
- **Attack mode selection**
- **Transformer mode selection**
- **Recursive behavior toggles**
- **Evaluation rules**

Most changes require modifying **only one line**.

---

## ⚠️ Performance Notes

- `cluster_bomb` can generate massive request volumes
- recursion should be used with filters enabled
- exclusion rules are strongly recommended

---

## 📌 Intended Audience

- Penetration testers
- Bug bounty hunters
- CTF players
- Advanced Burp Suite / Turbo Intruder users

This script assumes familiarity with:
- Burp Suite
- Turbo Intruder
- HTTP request structures

---

## 📄 License & Usage

This project is provided as-is for **educational and authorized security testing only**.

Always ensure you have explicit permission before testing any system.

---

## 🧩 Extensibility Ideas

- Recursive depth limits
- Payload deduplication
- Attack-mode inheritance during recursion
- Stateful discovery graphs
- Custom response scoring

---

## 🏁 Final Notes

This framework is intentionally **not minimalistic**.

It is designed to be:
- readable,
- modifiable,
- and adaptable during live testing.

If you understand what the script is doing at a glance —  
then it is working exactly as intended.
