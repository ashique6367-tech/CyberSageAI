# CyberSage AI

> **Multimodal Cybersecurity Investigation & Risk Correlation Assistant**  
> *Category: Best Use of Gemma 4*  
> *Architecture: Strict Single-File Runtime (`app.py`)*

---

## 1. Overview & Problem Statement

CyberSage AI is a defensive cybersecurity investigation assistant designed to help security analysts, IT administrators, and end-users safely inspect suspicious digital artifacts:
- **Suspicious URLs:** Static structural parsing, IDN/punycode detection, host confusion, IP host identification, brand impersonation, and URL shortener analysis without navigating to the target.
- **Phishing Emails & Messages:** NLP heuristics scanning for artificial urgency, coercive deadlines, credential harvesting (passwords, OTPs, seed phrases), financial extortion, and security bypass instructions.
- **Website Screenshots:** Upload validation and multimodal inspection for deceptive visual layouts, brand imitation banners, and credential-harvesting containers.
- **Security Logs:** Authentication brute-force clustering, SQL injection payloads, directory traversal, and command injection signatures.
- **Gemma 4 Multimodal Reasoning:** Semantic cognitive modeling and multimodal visual interpretation with strict prompt containment.
- **Correlation & Heuristic Risk Engine:** Multi-vector compound threat correlation, indicator de-duplication, and a transparent 0–100 heuristic risk score with prioritized defensive next steps.

---

## 2. Strict Single-File Architecture

Per the hackathon architectural requirements, the entire runtime application is contained in a single Python file (`app.py`), embedding:
1. Complete FastAPI backend and API routes (`GET /`, `GET /api/health`, `POST /api/investigations`).
2. Complete embedded responsive modern dark-navy UI with HTML5, CSS3, and vanilla JavaScript.
3. Deterministic static URL analyzer (zero network calls to user targets).
4. Deterministic message and email NLP heuristic scanner.
5. Screenshot file validator (magic bytes validation for PNG, JPEG, and WebP).
6. Security log pattern analyzer.
7. Gemma 4 Provider interface and adapters (Ollama, Hugging Face, OpenAI-compatible, and Demo fallback).
8. Evidence correlation, de-duplication, and transparent 0–100 scoring engine.
9. JSON export builder and print-ready report views.
10. Strict XSS and prompt-injection defenses (safe DOM rendering via `textContent`, Content Security Policy, and model prompt containment).

### Repository Structure
```text
CyberSage-AI/
├── TASK.md              # Original specification and hackathon guidelines
├── app.py               # Complete single-file backend, frontend, rules & AI engine
├── requirements.txt     # Python dependencies
├── .env.example         # Environment template with placeholders (no secrets)
├── .gitignore           # Git ignore rules for environments, caches & uploads
├── README.md            # System documentation, run instructions & judging script
└── tests/
    └── test_app.py      # Automated unit and integration test suite
```

---

## 3. Prerequisites & Installation

### Prerequisites
- Python 3.11 or Python 3.12+
- Standard modern web browser (Chrome, Edge, Firefox, Safari)

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd adityaraj
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize environment configuration:**
   ```bash
   cp .env.example .env
   ```

---

## 4. Running the Application

### Start Development Server
```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```
*(Alternatively, run directly via `python app.py`)*

### Access Dashboard
Open your web browser and navigate to:
```text
http://127.0.0.1:8000
```

---

## 5. Gemma 4 Configuration & Integration

CyberSage AI features a verified provider abstraction with support for live Gemma 4 endpoints and a transparent demo fallback.

### Verified Gemma 4 Model Variants
- `google/gemma-4-E4B-it` (Multimodal 4B Edge: Text + Vision, optimized for local inference)
- `google/gemma-4-E2B-it` (2B Edge: Lightweight text analysis)
- `google/gemma-4-26B-A4B-it` (26B Mixture-of-Experts with 3.8B active parameters)
- `google/gemma-4-31B-it` (31B Dense model for enterprise workstations)

### Option A: Local Inference via Ollama (Recommended)
1. Install and run [Ollama](https://ollama.com).
2. Pull the model:
   ```bash
   ollama run gemma4
   ```
3. Update `.env`:
   ```env
   GEMMA_PROVIDER=ollama
   GEMMA_MODEL=google/gemma-4-E4B-it
   GEMMA_API_BASE=http://localhost:11434/v1
   GEMMA_API_KEY=ollama
   ```
4. Restart CyberSage AI. The header status badge will display `Gemma 4: google/gemma-4-E4B-it (Connected)`.

### Option B: Hugging Face Inference API
1. Set in `.env`:
   ```env
   GEMMA_PROVIDER=huggingface
   GEMMA_MODEL=google/gemma-4-E4B-it
   GEMMA_API_KEY=hf_your_actual_token_here
   ```

### Option C: Transparent Demo Mode (Default)
When running without external AI credentials (`GEMMA_PROVIDER=demo`), CyberSage AI runs in **Demo Mode**:
- Every simulated observation is explicitly labeled: `[Demo Mode / Simulated Gemma 4]`.
- Output is never misattributed as live model inference.
- Full deterministic static analysis (URL, email, logs, image headers) runs with 100% fidelity.

---

## 6. Running Tests

CyberSage AI includes a comprehensive test suite covering static URL rules, NLP urgency/credential heuristics, log inspection, magic-bytes image validation, correlation, scoring caps, and demo providers.

Run the test suite:
```bash
python tests/test_app.py
```
*(Or with `pytest`: `pytest tests/`)*

**Result:**
```text
..............................
----------------------------------------------------------------------
Ran 30 tests in 0.026s

OK
```

---

## 7. Security, Privacy & Safety Safeguards

1. **Zero Active URL Navigation:** The analyzer statically parses URL components (`urllib.parse`, regex, IP checks). It NEVER visits, fetches, or triggers HTTP requests to user-submitted links.
2. **Untrusted Evidence Barrier & Prompt Injection Defense:** All user evidence is treated as untrusted input. In prompts sent to Gemma 4, explicit delimiter boundaries and system-level containment instructions prevent malicious text from overriding instructions or invoking tools.
3. **Safe DOM Rendering (XSS Immunity):** Untrusted inputs and model outputs are injected strictly through `element.textContent` or escaped text nodes. No raw `innerHTML` injection.
4. **Content Security Policy (CSP):** Delivered with strict security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`).
5. **In-Memory File Processing:** Uploaded screenshots are validated in memory and never written to public web-accessible directories.

---

## 8. Judging Walkthrough Demo Script (3–5 Minutes)

1. **Introduction (30s):**
   - Introduce CyberSage AI: a single-file multimodal cybersecurity investigation assistant built for the *Best Use of Gemma 4* category.
   - Point to the header badge showing the provider status.

2. **Test Case 1: Phishing Email + Shortener URL (1 min):**
   - Click the quick-fill button: `⚠️ Phishing Email + Shortener URL`.
   - Click **Analyze Evidence**.
   - Observe the truthful 4-stage analysis execution.
   - Highlight findings:
     - **Deterministic URL:** `bit.ly` shortener detected (+14 pts).
     - **Deterministic Text:** Urgent coercive language (+20 pts) & credential solicitation (+30 pts).
     - **Compound Threat Correlation:** Multi-vector attack flagged (coercive text + disguised URL, +15 pts).
     - **Gemma 4 AI Interpretation:** Semantic cognitive pressure assessment.
     - **Risk Score:** 79/100 (`Very high concern`).

3. **Test Case 2: Brand Impersonation / Punycode (1 min):**
   - Click `🛡️ Brand Impersonation / Punycode URL`.
   - Analyze: shows Punycode homograph (`xn--pple-43d.com`) and userinfo confusion (`apple.com:support@...`).
   - Risk score elevates with direct defensive recommendations.

4. **Test Case 3: Auth Brute-Force & Log Injection (45s):**
   - Click `📋 Auth Brute-Force & Log Injection`.
   - Analyzes rapid failed login attempts and SQL injection query payloads.

5. **Test Case 4: Benign Verification (30s):**
   - Click `✅ Normal Benign Message`.
   - Score resets to 0/100 (`Low concern`) with zero false findings.

6. **Export & Conclusion (30s):**
   - Click **Download JSON Report** to show the structured API contract.
   - Click **Print / Save PDF** to demonstrate printer-friendly report styling.
   - Conclude by stating the preliminary nature of defensive heuristics and the importance of evidence-backed analysis.

---

## 9. Known Limitations

- **Preliminary Heuristic Tool:** CyberSage AI is designed for rapid defensive triage and investigation. It is not an endpoint detection and response (EDR) agent or dynamic malware sandbox.
- **No Headless Browser Execution in MVP:** To ensure complete safety on consumer machines, URLs are analyzed statically rather than rendered via a headless browser.
- **Threat Intelligence:** External threat reputation adapters require individual API keys (e.g., VirusTotal) and are disabled by default to operate completely offline.
