# ThreatLens

ThreatLens is a lightweight Streamlit app that checks whether an **IP
address, domain, or URL** looks safe, suspicious, or malicious, using
**VirusTotal** and **WHOIS** evidence combined with an **AI-generated
explanation** from Gemini.

## Features

- Analyze an IP address, domain, or URL
- Input validation before any external API calls are made
- Evidence gathered from VirusTotal and WHOIS
- Knowledge-level-aware explanations (Beginner / Intermediate / Expert)
- Color-coded verdict: 🟢 SAFE · 🟠 SUSPICIOUS · 🔴 MALICIOUS · ⚪ UNKNOWN
- AI Insight card with a summary, key indicators, and a recommendation
- Expandable raw source evidence
- Individual source failures never crash the app — they're shown as
  "unavailable" and the analysis continues with whatever evidence exists

## Architecture

```text
app.py          → Streamlit UI, validation, orchestration, Gemini prompt
                   construction, Gemini call, results display
sources.py       → External intelligence source functions ONLY
                   (get_virustotal, get_whois, SOURCES)
```

Dependency direction is strictly one-way: `app.py` imports from
`sources.py`. `sources.py` never imports `app.py`, and has no knowledge
of Streamlit or Gemini.

### How the source registry works

`sources.py` exposes a plain dictionary:

```python
SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
```

`app.py` never calls `get_virustotal()` or `get_whois()` directly. It
always loops over the registry:

```python
for source_name, source_function in SOURCES.items():
    results[source_name] = source_function(target, target_type)
```

This means the UI, orchestration loop, Gemini prompt logic, and results
display never need to know how many sources exist or what they're
called.

### Adding a new intelligence source

To add a source such as AbuseIPDB, Shodan, or URLScan:

1. Write one function in `sources.py` that accepts `(target,
   target_type)` and returns a dict shaped like:

   ```python
   {"source": "NewSource", "status": "success", "data": {...}}
   # or
   {"source": "NewSource", "status": "error", "error": "..."}
   ```

2. Register it:

   ```python
   SOURCES["NewSource"] = get_newsource
   ```

That's it — no changes are needed to the Streamlit UI, the orchestration
loop, the Gemini prompt builder, or the results-display code.

## Environment Variables

| Variable             | Purpose                       |
|-----------------------|--------------------------------|
| `VIRUSTOTAL_API_KEY`  | VirusTotal API key             |
| `GEMINI_API_KEY`      | Google Gemini API key          |

## Installation

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key
```

## Running the app

```bash
streamlit run app.py
```

## Notes

- Verdicts are AI-assisted assessments based only on the evidence
  collected from VirusTotal and WHOIS — they are not a guarantee that a
  target is safe or malicious.
- If evidence is missing or insufficient, the app can (and will) return
  an `UNKNOWN` verdict rather than forcing a guess.