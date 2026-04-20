"""
Scoring engine — combines all analyzer results into a final
verdict (phishing / legitimate / uncertain) with confidence score.
"""

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring Weights
# ---------------------------------------------------------------------------

# Each signal contributes a weighted score towards phishing probability.
# The total is normalized to 0.0–1.0.

MAX_POSSIBLE_SCORE = 1.0


def compute_verdict(
    infrastructure: dict,
    textual: dict,
    metadata: dict,
) -> dict:
    """
    Combine all analyzer results into a final verdict.

    Returns:
        {
            "verdict": "phishing" | "legitimate" | "uncertain",
            "confidence": 0.0–1.0,
            "signal_breakdown": {...}
        }
    """
    score = 0.0
    signals = {}

    # ===================================================================
    # INFRASTRUCTURE SIGNALS
    # ===================================================================

    # 1. Authentication failures (SPF/DKIM/DMARC)
    sigs = infrastructure.get("signatures", {})
    auth_score = 0.0
    if sigs.get("spf") in ("fail", "softfail", "temperror", "permerror", "none"):
        auth_score += 0.05
    if sigs.get("dkim") in ("fail", "none", "not_found"):
        auth_score += 0.05
    if sigs.get("dmarc") in ("fail", "none", "temperror", "permerror"):
        auth_score += 0.05
    auth_score = min(auth_score, 0.15)
    score += auth_score
    signals["auth_failure"] = auth_score

    # 2. IP blacklisted
    ip_rep = infrastructure.get("ip_reputation", {})
    ip_score = 0.15 if ip_rep.get("blacklisted") else 0.0
    score += ip_score
    signals["ip_blacklisted"] = ip_score

    # 3. Typosquatted domains
    typo = infrastructure.get("typosquatting", {})
    typo_score = min(typo.get("count", 0) * 0.06, 0.12)
    score += typo_score
    signals["typosquatting"] = typo_score

    # 4. Double extension attachments
    dbl_ext = infrastructure.get("double_extensions", {})
    dbl_score = 0.10 if dbl_ext.get("count", 0) > 0 else 0.0
    score += dbl_score
    signals["double_extension"] = dbl_score

    # 5. Legitimate service abuse (slight positive signal)
    legit = infrastructure.get("legit_service_abuse", {})
    legit_score = min(legit.get("count", 0) * 0.02, 0.04)
    score += legit_score
    signals["legit_service_abuse"] = legit_score

    # 6. VirusTotal
    vt = infrastructure.get("virustotal", {})
    vt_mal = vt.get("total_malicious", 0)
    vt_sus = vt.get("total_suspicious", 0)
    vt_score = 0.0
    if vt_mal > 0:
        vt_score = min(vt_mal * 0.03, 0.10)
    elif vt_sus > 0:
        vt_score = min(vt_sus * 0.02, 0.06)
    score += vt_score
    signals["virustotal"] = vt_score

    # 7. URL analysis
    url_a = infrastructure.get("url_analysis", {})
    url_score = 0.0
    if url_a.get("has_at_symbol"):
        url_score += 0.03
    if url_a.get("avg_entropy", 0) > 4.5:
        url_score += 0.02
    if url_a.get("avg_length", 0) > 100:
        url_score += 0.02
    if url_a.get("max_dots", 0) > 5:
        url_score += 0.01
    # Check for IP-based URLs
    for detail in url_a.get("url_details", []):
        if detail.get("has_ip_address"):
            url_score += 0.03
            break
    url_score = min(url_score, 0.08)
    score += url_score
    signals["url_suspicious"] = url_score

    # 8. Young domain (WHOIS)
    whois_data = infrastructure.get("whois", {})
    whois_score = 0.0
    creation = whois_data.get("creation_date")
    if creation:
        try:
            from datetime import datetime
            # Try parsing the date
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
                try:
                    cd = datetime.strptime(str(creation)[:19], fmt)
                    age_days = (datetime.now() - cd).days
                    if age_days < 30:
                        whois_score = 0.05
                    elif age_days < 90:
                        whois_score = 0.03
                    elif age_days < 365:
                        whois_score = 0.01
                    break
                except ValueError:
                    continue
        except Exception:
            pass
    score += whois_score
    signals["young_domain"] = whois_score

    # ===================================================================
    # TEXTUAL SIGNALS
    # ===================================================================

    # 9. Urgency language
    urgency = textual.get("urgency", {})
    urg_matches = urgency.get("total_matches", 0)
    urg_score = min(urg_matches * 0.02, 0.08)
    score += urg_score
    signals["urgency_language"] = urg_score

    # 10. Action requests
    action = textual.get("action_requests", {})
    act_matches = action.get("total_matches", 0)
    act_score = min(act_matches * 0.02, 0.08)
    score += act_score
    signals["action_requests"] = act_score

    # 11. Financial/crypto patterns
    fin = textual.get("financial_crypto", {})
    fin_score = 0.0
    if fin.get("has_crypto"):
        fin_score += 0.05
    if fin.get("has_financial_language"):
        fin_score += 0.03
    fin_score = min(fin_score, 0.08)
    score += fin_score
    signals["financial_crypto"] = fin_score

    # 12. Foreign language
    foreign = textual.get("foreign_language", {})
    foreign_score = 0.0
    if foreign.get("non_english_ratio", 0) > 0.5:
        foreign_score = 0.05
    elif foreign.get("is_multilingual"):
        foreign_score = 0.02
    score += foreign_score
    signals["foreign_language"] = foreign_score

    # 13. Typos
    typos = textual.get("typos", {})
    typo_count = typos.get("typo_count", 0)
    total_checked = typos.get("total_checked", 1)
    typo_ratio = typo_count / max(total_checked, 1)
    typo_t_score = min(typo_ratio * 0.1, 0.03)
    score += typo_t_score
    signals["typos"] = typo_t_score

    # 14. Low readability (very simple text targeting less educated)
    fk = textual.get("flesch_kincaid", {})
    fk_grade = fk.get("grade_level", 6)
    read_score = 0.0
    if fk_grade < 5:
        read_score = 0.04
    elif fk_grade < 3:
        read_score = 0.02
    score += read_score
    signals["readability"] = read_score

    # 15. Character frequency anomaly
    char_freq = textual.get("char_frequency", {})
    if not char_freq.get("matches_english", True):
        char_score = 0.03
    else:
        char_score = 0.0
    score += char_score
    signals["char_anomaly"] = char_score

    # ===================================================================
    # METADATA SIGNALS
    # ===================================================================

    # 16. Name-username mismatch (low correlation = suspicious)
    name_corr = metadata.get("name_username_correlation", {})
    corr_score_val = name_corr.get("correlation_score", 0)
    name_score = 0.0
    if name_corr.get("display_name") and corr_score_val == 0:
        name_score = 0.03
    score += name_score
    signals["name_mismatch"] = name_score

    # 17. Phishing words present
    phish_words = metadata.get("unused_phishing_words", {})
    pw_count = phish_words.get("phishing_word_count", 0)
    pw_score = min(pw_count * 0.015, 0.12)
    score += pw_score
    signals["phishing_words"] = pw_score

    # 20. Brand impersonation
    brand_imp = metadata.get("brand_impersonation", {})
    brand_score = 0.20 if brand_imp.get("is_impersonation") else 0.0
    score += brand_score
    signals["brand_impersonation"] = brand_score

    # 18. PDF/OCR visual verdict
    pdf_ocr = metadata.get("pdf_ocr", {})
    visual_verdict = pdf_ocr.get("visual_verdict", "unknown")
    vis_score = 0.0
    if visual_verdict == "phishing":
        vis_score = 0.05
    elif visual_verdict == "suspicious":
        vis_score = 0.02
    score += vis_score
    signals["visual_analysis"] = vis_score

    # 21. Sparse body with external link (link-only phishing)
    body_words = textual.get("body_word_count", 999)
    url_count = len(url_a.get("url_details", []))
    sparse_score = 0.0
    if body_words < 30 and url_count >= 1:
        sparse_score = 0.15
    elif body_words < 60 and url_count >= 1:
        sparse_score = 0.08
    score += sparse_score
    signals["sparse_body_with_link"] = sparse_score

    # 19. Ptech/Ptac heuristic
    ptech = metadata.get("ptech_ptac", {})
    ptech_val = ptech.get("ptech_score", 0)
    ptech_score = ptech_val * 0.08  # Scale to max 0.08
    score += ptech_score
    signals["ptech_ptac"] = round(ptech_score, 4)

    # ===================================================================
    # Signal correlation bonus
    # ===================================================================
    # If multiple high-signal categories fire together, boost confidence
    high_signals = sum(
        1 for k, v in signals.items()
        if v >= 0.05 and k in (
            "auth_failure", "ip_blacklisted", "typosquatting",
            "double_extension", "urgency_language", "action_requests",
            "brand_impersonation", "sparse_body_with_link",
        )
    )
    if high_signals >= 3:
        bonus = 0.05
        score += bonus
        signals["correlation_bonus"] = bonus
    else:
        signals["correlation_bonus"] = 0.0

    # ===================================================================
    # Normalize and determine verdict
    # ===================================================================
    confidence = min(score, MAX_POSSIBLE_SCORE)
    confidence = round(confidence, 4)

    if confidence >= 0.35:
        verdict = "phishing"
    elif confidence >= 0.20:
        verdict = "uncertain"
    else:
        verdict = "legitimate"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "signal_breakdown": signals,
        "raw_score": round(score, 4),
    }
