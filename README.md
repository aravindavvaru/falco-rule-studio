# Falco Rule Studio

> AI-powered rule generator, explainer, validator, and optimizer for [Falco](https://falco.org) — the CNCF graduated runtime security tool.

**The missing feature in the Falco ecosystem.** No existing Falco tooling lets you write rules in natural language, understand what a rule actually does, or catch errors before deploying to production. This fills that gap.

---

## Features

| Tab | What it does |
|-----|-------------|
| **Generate** | Describe a threat in plain English → get production-ready Falco YAML with macros, lists, and MITRE ATT&CK tags |
| **Explain** | Paste any Falco rule → get a plain-English breakdown with security context and tuning tips |
| **Validate** | YAML syntax check + required field validation + best-practice linting |
| **Optimize** | AI reviews condition ordering, false-positive risk, and coverage gaps → returns an improved rule with a change summary |
| **AI Chat** | Multi-turn conversation with a Falco expert — ask about syscalls, eBPF, MITRE mappings, or rule debugging |

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/aravindavvaru/falco-rule-studio.git
cd falco-rule-studio
```

### 2. Set your API key

```bash
cp .env.example .env
# Edit .env and add your Anthropic API key
```

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Get a key at [console.anthropic.com](https://console.anthropic.com).

### 3. Run

**With Python:**

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**With Docker:**

```bash
docker compose up
```

Open [http://localhost:8000](http://localhost:8000)

---

## Project Structure

```
falco-rule-studio/
├── app/
│   ├── main.py          # FastAPI app — 6 REST endpoints
│   ├── rule_engine.py   # AI logic — generate, explain, validate, optimize, chat
│   ├── models.py        # Pydantic request/response schemas
│   └── examples.py      # Sample rules, prompts, Falco field reference
├── static/
│   ├── index.html       # Single-page web UI — 5 tabs
│   ├── style.css        # Dark theme with YAML syntax highlighting
│   └── app.js           # Vanilla JS — no framework
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## API Reference

All endpoints accept and return JSON.

### `POST /api/generate`

Convert a natural language description into a Falco rule.

```json
{
  "description": "Alert when kubectl is executed inside a pod",
  "context": "Kubernetes environment",
  "severity": "WARNING",
  "tags": []
}
```

### `POST /api/explain`

Explain a Falco rule in plain English.

```json
{
  "rule_yaml": "- rule: ...\n  condition: ..."
}
```

### `POST /api/validate`

Validate a Falco rule for syntax and best practices.

```json
{
  "rule_yaml": "- rule: ..."
}
```

### `POST /api/optimize`

Get optimization suggestions for a Falco rule.

```json
{
  "rule_yaml": "- rule: ..."
}
```

### `POST /api/chat`

Multi-turn conversation with the Falco AI expert.

```json
{
  "message": "How do I detect cryptomining?",
  "history": []
}
```

### `GET /api/examples`

Returns example rules and prompt suggestions for the UI.

---

## Example — Generate a Rule

**Input:**
> "Alert when a process inside a container tries to read /etc/shadow"

**Output:**
```yaml
- list: sensitive_files
  items: [/etc/shadow, /etc/gshadow, /etc/master.passwd]

- rule: Sensitive file read in container
  desc: >
    A process attempted to read a sensitive credential file inside a container.
    This may indicate credential harvesting by an attacker.
  condition: >
    open_read and
    container and
    fd.name in (sensitive_files) and
    not proc.name in (known_credential_access_tools)
  output: >
    Sensitive file read inside container
    (user=%user.name command=%proc.cmdline file=%fd.name
     container=%container.name image=%container.image.repository
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [container, filesystem, mitre_credential_access, T1003]
```

---

## Tech Stack

- **Backend:** FastAPI + Uvicorn
- **AI:** Anthropic Claude (`claude-sonnet-4-6`)
- **Frontend:** Vanilla HTML/CSS/JS (zero dependencies)
- **Rule Validation:** PyYAML + Claude

---

## Why This Matters

Falco ships with ~100 default rules written by security experts. But teams need custom rules for their own workloads — and writing them requires deep knowledge of:

- Sysdig filter syntax
- Linux syscalls
- Falco's field schema (300+ fields)
- MITRE ATT&CK mappings
- Performance trade-offs in condition ordering

**Falco Rule Studio removes that barrier.** Describe what you want to detect. Get a rule that works.

---

## What Falco Is

[Falco](https://falco.org) is a CNCF graduated project that detects runtime security threats by parsing Linux syscalls via eBPF. It powers runtime security for thousands of Kubernetes clusters worldwide. This project builds tooling on top of Falco's rule system — it does not modify Falco itself.

---

## License

MIT
