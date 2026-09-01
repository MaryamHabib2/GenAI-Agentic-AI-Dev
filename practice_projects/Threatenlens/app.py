"""
ThreatLens — app.py

Streamlit UI, input validation, orchestration, Gemini prompt construction,
Gemini call, and results display all live here.

Only sources.py is imported for external intelligence gathering. New
sources are picked up automatically through sources.SOURCES — this file
never needs to change to support a new source.
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import ipaddress
import json
import os
import re
from urllib.parse import urlparse

import streamlit as st
from dotenv import load_dotenv
from google import genai

from sources import SOURCES

load_dotenv()


# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------

st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")

VERDICT_STYLES = {
    "SAFE": {"color": "#1e7e34", "bg": "#d4edda", "emoji": "🟢"},
    "SUSPICIOUS": {"color": "#8a6100", "bg": "#fff3cd", "emoji": "🟠"},
    "MALICIOUS": {"color": "#a71d2a", "bg": "#f8d7da", "emoji": "🔴"},
    "UNKNOWN": {"color": "#495057", "bg": "#e2e3e5", "emoji": "⚪"},
}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_ip(value):
    try:
        ipaddress.ip_address(value.strip())
        return True, None
    except ValueError:
        return False, "That doesn't look like a valid IPv4 or IPv6 address."


def validate_domain(value):
    value = value.strip()
    if DOMAIN_PATTERN.match(value):
        return True, None
    return False, "That doesn't look like a valid domain (e.g. example.com)."


def validate_url(value):
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        return False, "URL must start with http:// or https://."
    if not parsed.netloc:
        return False, "URL must contain a valid host (e.g. https://example.com)."
    return True, None


def validate_input(target_type, value):
    if not value or not value.strip():
        return False, "Please enter a value to analyze."

    if target_type == "IP Address":
        return validate_ip(value)
    if target_type == "Domain":
        return validate_domain(value)
    if target_type == "URL":
        return validate_url(value)

    return False, "Unknown target type."


# ---------------------------------------------------------------------------
# Gemini prompt builder
# ---------------------------------------------------------------------------

KNOWLEDGE_LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Explain the result for a beginner. Avoid unnecessary cybersecurity "
        "jargon, and explain any terms you must use in simple language. "
        "Clearly explain what the verdict means in practical terms and give "
        "simple, actionable advice."
    ),
    "Intermediate": (
        "Explain the result for someone with moderate security knowledge. "
        "Use moderate cybersecurity terminology, explain the important "
        "indicators found, explain why the evidence affects the verdict, "
        "and provide practical security recommendations."
    ),
    "Expert": (
        "Explain the result for a security expert. Use precise technical "
        "cybersecurity terminology, discuss the relevant indicators and "
        "evidence, distinguish between strong and weak signals, avoid "
        "oversimplification, and mention uncertainty or limitations in the "
        "evidence where appropriate."
    ),
}


def build_gemini_prompt(target, target_type, knowledge_level, results):
    """Build a knowledge-level-specific prompt for Gemini from source results."""
    level_instruction = KNOWLEDGE_LEVEL_INSTRUCTIONS[knowledge_level]

    prompt = f"""
You are a cybersecurity analysis assistant inside a tool called ThreatLens.

Target: {target}
Target type: {target_type}
Knowledge level for explanation: {knowledge_level}

Below is the raw evidence collected from threat-intelligence sources.
Use ONLY this evidence. Do not claim that information exists if it is not
present in the supplied results. If the evidence is insufficient to reach
a confident conclusion, say so and use the UNKNOWN verdict.

Evidence:
{json.dumps(results, indent=2, default=str)}

Instructions:
1. Determine an overall verdict based strictly on the evidence above.
2. {level_instruction}
3. Respond with ONLY a single JSON object (no markdown, no code fences, no
   extra commentary) in exactly this shape:

{{
  "verdict": "SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN",
  "confidence": "LOW | MEDIUM | HIGH",
  "summary": "Short explanation appropriate to the knowledge level",
  "insights": ["Insight 1", "Insight 2", "Insight 3"],
  "recommendation": "Recommended action for the user"
}}

Only use the verdict values SAFE, SUSPICIOUS, MALICIOUS, or UNKNOWN.
Only use the confidence values LOW, MEDIUM, or HIGH.
"""
    return prompt.strip()


# ---------------------------------------------------------------------------
# Gemini call
# ---------------------------------------------------------------------------

def call_gemini(prompt):
    """Call Gemini and parse the structured JSON response. Never raises."""
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return _fallback_result("GEMINI_API_KEY is not set.")

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        raw_text = (response.text or "").strip()

        # Defensively strip markdown code fences if the model adds them.
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`")
            raw_text = raw_text.replace("json\n", "", 1).strip()

        parsed = json.loads(raw_text)
        return _validate_gemini_result(parsed)

    except json.JSONDecodeError:
        return _fallback_result("Gemini returned a response that wasn't valid JSON.")
    except Exception as exc:  # noqa: BLE001 - never let Gemini crash the app
        return _fallback_result(f"Error calling Gemini: {exc}")


def _validate_gemini_result(parsed):
    """Make sure the parsed Gemini result has the fields/values we expect."""
    allowed_verdicts = {"SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}
    allowed_confidence = {"LOW", "MEDIUM", "HIGH"}

    verdict = str(parsed.get("verdict", "UNKNOWN")).upper()
    if verdict not in allowed_verdicts:
        verdict = "UNKNOWN"

    confidence = str(parsed.get("confidence", "LOW")).upper()
    if confidence not in allowed_confidence:
        confidence = "LOW"

    insights = parsed.get("insights", [])
    if not isinstance(insights, list):
        insights = [str(insights)]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": str(parsed.get("summary", "No summary provided.")),
        "insights": [str(i) for i in insights],
        "recommendation": str(parsed.get("recommendation", "No recommendation provided.")),
    }


def _fallback_result(error_message):
    """A safe UNKNOWN result used whenever Gemini can't be trusted/parsed."""
    return {
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "summary": "The AI analysis could not be completed.",
        "insights": [error_message],
        "recommendation": "Try again, or review the raw source evidence below manually.",
    }


# ---------------------------------------------------------------------------
# Result formatting / display
# ---------------------------------------------------------------------------

def display_verdict_card(ai_result):
    style = VERDICT_STYLES.get(ai_result["verdict"], VERDICT_STYLES["UNKNOWN"])

    st.markdown(
        f"""
        <div style="
            background-color:{style['bg']};
            color:{style['color']};
            padding: 1.1rem 1.3rem;
            border-radius: 10px;
            border: 1px solid {style['color']}33;
            margin-bottom: 1rem;
        ">
            <div style="font-size: 1.4rem; font-weight: 700;">
                {style['emoji']} {ai_result['verdict']}
            </div>
            <div style="font-size: 0.95rem; opacity: 0.85;">
                Confidence: {ai_result['confidence']}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(
        "This is an AI-assisted assessment based on the available VirusTotal "
        "and WHOIS evidence — not an absolute guarantee of safety."
    )


def display_ai_insight_card(ai_result):
    st.subheader("AI Insight")
    st.write(ai_result["summary"])

    if ai_result["insights"]:
        st.markdown("**Why:**")
        for insight in ai_result["insights"]:
            st.markdown(f"- {insight}")

    st.markdown("**Recommendation:**")
    st.write(ai_result["recommendation"])


def display_source_details(results):
    with st.expander("▼ Source Details"):
        for source_name, result in results.items():
            st.markdown(f"**{source_name}**")
            if result.get("status") == "success":
                st.json(result.get("data", {}))
            else:
                st.warning(f"{source_name} unavailable: {result.get('error', 'Unknown error')}")


# ---------------------------------------------------------------------------
# Analysis orchestration
# ---------------------------------------------------------------------------

def run_analysis(target, target_type, knowledge_level):
    results = {}

    # Iterate the source registry — this loop never changes when new
    # sources are added to sources.SOURCES.
    for source_name, source_function in SOURCES.items():
        try:
            results[source_name] = source_function(target, target_type)
        except Exception as exc:  # noqa: BLE001 - a broken source must not crash the app
            results[source_name] = {
                "source": source_name,
                "status": "error",
                "error": f"Unhandled exception in source: {exc}",
            }

    prompt = build_gemini_prompt(target, target_type, knowledge_level, results)
    ai_result = call_gemini(prompt)

    return results, ai_result


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------

st.title("🛡️ ThreatLens")
st.caption("Check whether an IP address, domain, or URL looks safe, suspicious, or malicious.")

target_type = st.radio("Target Type", ["IP Address", "Domain", "URL"], horizontal=True)

placeholders = {
    "IP Address": "8.8.8.8",
    "Domain": "example.com",
    "URL": "https://example.com/login",
}
target_value = st.text_input("Enter the target", placeholder=placeholders[target_type])

knowledge_level = st.radio(
    "How should we explain the result?",
    ["Beginner", "Intermediate", "Expert"],
    horizontal=True,
)

analyze_clicked = st.button("Analyze", type="primary")

if analyze_clicked:
    is_valid, error_message = validate_input(target_type, target_value)

    if not is_valid:
        st.error(error_message)
    else:
        with st.spinner("Analyzing target..."):
            results, ai_result = run_analysis(target_value.strip(), target_type, knowledge_level)

        st.markdown("---")
        st.markdown(f"**Target:** `{target_value.strip()}`")
        st.markdown(f"**Type:** {target_type}")

        display_verdict_card(ai_result)
        display_ai_insight_card(ai_result)
        display_source_details(results)
