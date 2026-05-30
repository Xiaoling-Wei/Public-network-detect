"""
AI Analyzer — Multi-provider integration (OpenAI / Gemini / Claude)
"""

import json
from ai.providers import call_provider, parse_response, PROVIDER_CONFIG


def analyze_with_ai(scan_summary: dict, provider: str, api_key: str, model: str) -> dict:
    """
    Send scan results to the selected AI provider and return structured analysis.

    Returns dict with keys:
        overall_assessment, risk_summary, recommendations, safe_to_use, error
    """
    fallback = {
        "overall_assessment": "",
        "risk_summary": "",
        "recommendations": [],
        "safe_to_use": True,
        "error": "",
    }

    if not api_key:
        fallback["error"] = f"No API key configured for {PROVIDER_CONFIG.get(provider, {}).get('name', provider)}. Add it in Settings."
        fallback["overall_assessment"] = _rule_based_assessment(scan_summary)
        return fallback

    if not model:
        model = PROVIDER_CONFIG.get(provider, {}).get("default_model", "")

    try:
        report = _build_report_payload(scan_summary)
        user_message = (
            "Please analyze the following network security scan report:\n\n"
            + json.dumps(report, indent=2)
        )

        raw = call_provider(provider, api_key, model, user_message)
        result = parse_response(raw)
        result.setdefault("error", "")
        return result

    except Exception as e:
        err = str(e)
        # Friendly messages for common errors
        if "401" in err or "invalid_api_key" in err.lower() or "authentication" in err.lower():
            fallback["error"] = f"Invalid API key for {provider}. Please check Settings."
        elif "429" in err or "rate" in err.lower() or "quota" in err.lower():
            fallback["error"] = "API rate limit reached. Please try again later."
        elif "JSONDecodeError" in type(e).__name__:
            fallback["error"] = f"AI returned unexpected format: {err}"
        else:
            fallback["error"] = f"AI analysis failed: {err}"

        fallback["overall_assessment"] = _rule_based_assessment(scan_summary)
        return fallback


def _build_report_payload(scan_summary: dict) -> dict:
    info = scan_summary.get("network_info", {})
    results = scan_summary.get("results", {})

    checks = {}
    for key, val in results.items():
        checks[val.get("check", key)] = {
            "status": val.get("status", "unknown"),
            "detail": val.get("detail", ""),
        }

    return {
        "network_name": info.get("ssid", "Unknown"),
        "wifi_encryption": info.get("wifi_security", "Unknown"),
        "has_internet": info.get("has_internet", False),
        "dns_servers": info.get("dns_servers", []),
        "security_score": scan_summary.get("score", 0),
        "risk_level": scan_summary.get("risk_level", "Unknown"),
        "check_results": checks,
    }


def _rule_based_assessment(scan_summary: dict) -> str:
    score = scan_summary.get("score", 5)
    dangers = [
        val.get("check", k)
        for k, val in scan_summary.get("results", {}).items()
        if val.get("status") == "danger"
    ]
    if dangers:
        return f"High-risk issues detected ({', '.join(dangers)}). Use a VPN or avoid this network."
    elif score >= 8:
        return "This network appears safe for general use."
    elif score >= 6:
        return "This network is mostly safe. Avoid sensitive transactions."
    else:
        return f"Security score is low ({score}/10). Avoid banking or logging into important accounts."
