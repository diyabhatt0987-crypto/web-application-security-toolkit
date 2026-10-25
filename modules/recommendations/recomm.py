"""
Recommendation Engine
Web Application Security Toolkit

This module generates defensive security recommendations
from scan results produced by the Web Application Security Toolkit.

Modes:
    Normal -> Rule-based recommendations
    AI     -> Local AI-style contextual recommendations

No external API or API key is required.
"""

# ============================================================
# RECOMMENDATION RULES
# ============================================================

RECOMMENDATION_RULES = {
    "server information disclosure": {
        "severity": "Low",
        "recommendation": (
            "Minimize unnecessary server and technology information "
            "disclosure. Hide server version details where possible."
        )
    },

    "information disclosure": {
        "severity": "Low",
        "recommendation": (
            "Review the exposed information and remove unnecessary "
            "details that could help an attacker understand the "
            "application or server configuration."
        )
    },

    "http methods": {
        "severity": "Medium",
        "recommendation": (
            "Disable unnecessary HTTP methods and allow only the "
            "methods required by the application."
        )
    },

    "directory listing": {
        "severity": "Medium",
        "recommendation": (
            "Disable directory indexing where it is not required "
            "and restrict access to sensitive directories."
        )
    },

    "sensitive paths": {
        "severity": "High",
        "recommendation": (
            "Restrict access to sensitive paths such as administrative, "
            "configuration, backup, and internal resources."
        )
    },

    "https": {
        "severity": "High",
        "recommendation": (
            "Enable HTTPS with a valid TLS certificate and redirect "
            "HTTP traffic to HTTPS."
        )
    },

    "ssl": {
        "severity": "High",
        "recommendation": (
            "Review the SSL/TLS configuration and use secure protocols "
            "and properly configured certificates."
        )
    },

    "tls": {
        "severity": "High",
        "recommendation": (
            "Review the TLS configuration and use currently supported "
            "secure protocols and valid certificates."
        )
    },

    "security headers": {
        "severity": "Medium",
        "recommendation": (
            "Configure appropriate HTTP security headers according "
            "to the application's security requirements."
        )
    },

    "missing security header": {
        "severity": "Medium",
        "recommendation": (
            "Add the missing security header and configure it "
            "according to the application's requirements."
        )
    },

    "cookie": {
        "severity": "Medium",
        "recommendation": (
            "Review application cookies and apply appropriate "
            "security attributes such as Secure, HttpOnly, and "
            "SameSite where applicable."
        )
    }
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _clean_text(value):
    """
    Convert a value into clean searchable text.
    """

    if value is None:
        return ""

    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value).strip()


def _is_empty(value):
    """
    Check whether a value is effectively empty.
    """

    if value is None:
        return True

    if isinstance(value, str):
        return not value.strip()

    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0

    return False


def _is_negative_value(value):
    """
    Determine whether a scanner value appears to indicate
    a security issue.

    This is intentionally conservative because scanner modules
    can use different wording.
    """

    if value is None:
        return False

    if isinstance(value, bool):
        return value is False

    if isinstance(value, (list, tuple)):
        return len(value) > 0

    text = str(value).lower().strip()

    negative_words = [
        "not detected",
        "not enabled",
        "disabled",
        "missing",
        "exposed",
        "vulnerable",
        "vulnerability",
        "insecure",
        "unsafe",
        "weak",
        "open",
        "allowed",
        "accessible",
        "enabled",
        "found",
        "disclosed",
        "publicly accessible",
        "directory listing",
        "server information",
        "sensitive path"
    ]

    for word in negative_words:
        if word in text:
            return True

    return False


def _is_positive_value(value):
    """
    Determine whether a scanner value appears to indicate
    a positive/security-protected condition.
    """

    if value is None:
        return False

    if isinstance(value, bool):
        return value is True

    text = str(value).lower().strip()

    positive_words = [
        "enabled",
        "secure",
        "protected",
        "present",
        "detected",
        "not found",
        "not exposed",
        "restricted",
        "disabled",
        "https enabled",
        "https detected"
    ]

    for word in positive_words:
        if word in text:
            return True

    return False


# ============================================================
# FIND RULE
# ============================================================

def find_rule(finding_name):
    """
    Find a matching recommendation rule.
    """

    if not finding_name:
        return None

    name = str(finding_name).lower().strip()

    if name in RECOMMENDATION_RULES:
        return RECOMMENDATION_RULES[name]

    for rule_name, rule_data in RECOMMENDATION_RULES.items():

        if rule_name in name:
            return rule_data

        if name in rule_name:
            return rule_data

    return None


# ============================================================
# RECURSIVE SCAN RESULT EXTRACTION
# ============================================================

def _extract_findings_from_value(
    value,
    current_key="",
    results=None,
    parent_path=""
):
    """
    Recursively inspect scanner output.

    This is important because the GUI may provide results such as:

        {
            "Reconnaissance": {...},
            "Security Analysis": {...},
            "Vulnerability Assessment": {...}
        }

    instead of:

        {
            "findings": [...]
        }
    """

    if results is None:
        results = []

    key_text = _clean_text(current_key)
    path = parent_path

    if key_text:

        if path:
            path = f"{path} -> {key_text}"
        else:
            path = key_text

    # --------------------------------------------------------
    # Dictionary
    # --------------------------------------------------------

    if isinstance(value, dict):

        # Direct finding-style dictionary
        finding_name = (
            value.get("name")
            or value.get("finding")
            or value.get("title")
            or value.get("issue")
        )

        if finding_name:

            evidence = (
                value.get("evidence")
                or value.get("details")
                or value.get("description")
                or ""
            )

            severity = value.get("severity")

            results.append(
                {
                    "name": _clean_text(finding_name),
                    "evidence": _clean_text(evidence),
                    "severity": severity,
                    "path": path
                }
            )

        # Explicit findings container
        if "findings" in value:

            findings_value = value.get("findings")

            if isinstance(findings_value, list):

                for finding in findings_value:

                    _extract_findings_from_value(
                        finding,
                        "finding",
                        results,
                        path
                    )

            elif isinstance(findings_value, dict):

                for finding_name, finding_data in findings_value.items():

                    if isinstance(finding_data, dict):

                        evidence = (
                            finding_data.get("evidence")
                            or finding_data.get("details")
                            or finding_data.get("description")
                            or ""
                        )

                        severity = finding_data.get("severity")

                    else:

                        evidence = finding_data
                        severity = None

                    results.append(
                        {
                            "name": _clean_text(finding_name),
                            "evidence": _clean_text(evidence),
                            "severity": severity,
                            "path": path
                        }
                    )

        # Recursively inspect every other field
        for key, item in value.items():

            if key == "findings":
                continue

            _extract_findings_from_value(
                item,
                key,
                results,
                path
            )

        return results

    # --------------------------------------------------------
    # List / Tuple
    # --------------------------------------------------------

    if isinstance(value, (list, tuple)):

        for index, item in enumerate(value):

            _extract_findings_from_value(
                item,
                current_key,
                results,
                path
            )

        return results

    # --------------------------------------------------------
    # Scalar value
    # --------------------------------------------------------

    if current_key:

        value_text = _clean_text(value)

        if not _is_empty(value_text):

            results.append(
                {
                    "name": key_text,
                    "evidence": value_text,
                    "severity": None,
                    "path": path
                }
            )

    return results


def _collect_scan_items(scan_result):
    """
    Return normalized scanner items from any supported GUI structure.
    """

    if not isinstance(scan_result, dict):
        return []

    raw_items = _extract_findings_from_value(
        scan_result
    )

    cleaned = []
    seen = set()

    for item in raw_items:

        name = _clean_text(item.get("name"))
        evidence = _clean_text(item.get("evidence"))
        severity = item.get("severity")

        if not name:
            continue

        identifier = (
            name.lower(),
            evidence.lower()
        )

        if identifier in seen:
            continue

        seen.add(identifier)

        cleaned.append(
            {
                "name": name,
                "evidence": evidence,
                "severity": severity,
                "path": item.get("path", "")
            }
        )

    return cleaned


# ============================================================
# FINDING CLASSIFICATION
# ============================================================

def _looks_like_issue(name, evidence):
    """
    Determine whether an extracted scanner item appears
    to represent a security issue.
    """

    combined = (
        f"{_clean_text(name)} "
        f"{_clean_text(evidence)}"
    ).lower()

    issue_words = [
        "missing",
        "not detected",
        "not enabled",
        "disabled",
        "exposed",
        "vulnerable",
        "insecure",
        "unsafe",
        "weak",
        "sensitive",
        "directory listing",
        "information disclosure",
        "server information",
        "open method",
        "unnecessary method",
        "not secure",
        "over http",
        "uses get",
        "external destination",
        "csrf protection",
        "server error",
    ]

    for word in issue_words:

        if word in combined:
            return True

    return False


# ============================================================
# NORMAL RECOMMENDATION CREATION
# ============================================================

def _build_normal_recommendation(item):
    """
    Convert one normalized scan item into a normal recommendation.
    """

    finding_name = item.get("name", "Unknown Finding")
    evidence = item.get("evidence", "")
    scanner_severity = item.get("severity")

    rule = find_rule(finding_name)

    # Try the evidence too because some scanners put
    # the actual issue in the evidence text.
    if rule is None and evidence:
        rule = find_rule(evidence)

    if rule:

        severity = (
            scanner_severity
            or rule.get("severity")
            or "Medium"
        )

        recommendation = rule.get(
            "recommendation",
            "Review this finding manually."
        )

    else:

        severity = scanner_severity or "Medium"

        recommendation = (
            "Review this finding manually, verify whether the "
            "exposure is required, and reduce unnecessary access "
            "or information exposure."
        )

    return {
        "finding": finding_name,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "mode": "Normal"
    }


# ============================================================
# NORMAL RECOMMENDATIONS
# ============================================================

def generate_normal_recommendations(scan_result):
    """
    Generate rule-based defensive recommendations.

    Unlike the previous implementation, this function does not
    require findings to exist at the top level of the result.
    """

    if not isinstance(scan_result, dict):
        return {
            "success": False,
            "mode": "Normal",
            "message": "Invalid scan result.",
            "recommendations": []
        }

    items = _collect_scan_items(scan_result)

    recommendations = []

    for item in items:

        name = item.get("name", "")
        evidence = item.get("evidence", "")

        # Only create issue recommendations when the scanner
        # output appears to indicate an actual problem.
        if _looks_like_issue(name, evidence):

            recommendations.append(
                _build_normal_recommendation(item)
            )

    # If no obvious issue was detected, provide hardening advice
    # instead of returning an empty screen.
    if not recommendations:

        recommendations = _generate_hardening_recommendations(
            scan_result,
            items,
            mode="Normal"
        )

    return {
        "success": True,
        "mode": "Normal",
        "message": (
            "Rule-based security recommendation analysis "
            "completed successfully."
        ),
        "recommendations": recommendations
    }


# ============================================================
# HARDENING RECOMMENDATIONS
# ============================================================

def _generate_hardening_recommendations(
    scan_result,
    items,
    mode="Normal"
):
    """
    Generate useful defensive guidance even when the scanner
    does not report an obvious vulnerability.

    This prevents the GUI from showing:
        No recommendations available.
    """

    recommendations = []

    names = [
        _clean_text(item.get("name")).lower()
        for item in items
    ]

    all_text = " ".join(
        [
            _clean_text(item.get("name"))
            + " "
            + _clean_text(item.get("evidence"))
            for item in items
        ]
    ).lower()

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if (
        "https" in all_text
        or "ssl" in all_text
        or "tls" in all_text
    ):

        recommendations.append(
            {
                "finding": "HTTPS / Transport Security",
                "severity": "Hardening",
                "evidence": (
                    "The scan evaluated HTTPS/TLS related information."
                ),
                "recommendation": (
                    "Keep HTTPS enabled, use a valid TLS certificate, "
                    "redirect HTTP traffic to HTTPS, and periodically "
                    "review the TLS configuration."
                ),
                "mode": mode
            }
        )

    # --------------------------------------------------------
    # Server information
    # --------------------------------------------------------

    if (
        "server" in all_text
        or "technology" in all_text
        or "information" in all_text
    ):

        recommendations.append(
            {
                "finding": "Server Information Hardening",
                "severity": "Hardening",
                "evidence": (
                    "The scan evaluated server or technology information."
                ),
                "recommendation": (
                    "Minimize unnecessary server banners and technology "
                    "disclosure. Avoid exposing detailed version "
                    "information unless it is required."
                ),
                "mode": mode
            }
        )

    # --------------------------------------------------------
    # HTTP methods
    # --------------------------------------------------------

    if (
        "http method" in all_text
        or "methods" in all_text
    ):

        recommendations.append(
            {
                "finding": "HTTP Method Hardening",
                "severity": "Hardening",
                "evidence": (
                    "The scan evaluated supported HTTP methods."
                ),
                "recommendation": (
                    "Allow only HTTP methods required by the application "
                    "and disable unnecessary methods."
                ),
                "mode": mode
            }
        )

    # --------------------------------------------------------
    # Directory listing
    # --------------------------------------------------------

    if (
        "directory" in all_text
        or "listing" in all_text
    ):

        recommendations.append(
            {
                "finding": "Directory Listing Hardening",
                "severity": "Hardening",
                "evidence": (
                    "The scan evaluated directory listing or "
                    "directory exposure."
                ),
                "recommendation": (
                    "Keep directory indexing disabled unless it is "
                    "specifically required. Review public directories "
                    "for unnecessary files and resources."
                ),
                "mode": mode
            }
        )

    # --------------------------------------------------------
    # Sensitive paths
    # --------------------------------------------------------

    if (
        "sensitive path" in all_text
        or "sensitive paths" in all_text
    ):

        recommendations.append(
            {
                "finding": "Sensitive Path Hardening",
                "severity": "Hardening",
                "evidence": (
                    "The scan evaluated potentially sensitive paths."
                ),
                "recommendation": (
                    "Review administrative, configuration, backup, "
                    "and internal paths. Ensure sensitive resources "
                    "require appropriate authorization."
                ),
                "mode": mode
            }
        )

    # --------------------------------------------------------
    # Security headers
    # --------------------------------------------------------

    if (
        "security header" in all_text
        or "header" in all_text
    ):

        recommendations.append(
            {
                "finding": "HTTP Security Header Hardening",
                "severity": "Hardening",
                "evidence": (
                    "The scan evaluated HTTP response headers."
                ),
                "recommendation": (
                    "Review security-related response headers and "
                    "configure protections appropriate for the "
                    "application."
                ),
                "mode": mode
            }
        )

    # --------------------------------------------------------
    # Generic fallback
    # --------------------------------------------------------

    if not recommendations:

        recommendations.append(
            {
                "finding": "General Security Hardening",
                "severity": "Informational",
                "evidence": (
                    "The scan completed and returned usable scan data, "
                    "but no specific security issue was identified "
                    "by the recommendation rules."
                ),
                "recommendation": (
                    "Keep software and dependencies updated, minimize "
                    "unnecessary services and information disclosure, "
                    "apply least privilege, review access controls, "
                    "and periodically repeat authorized security scans."
                ),
                "mode": mode
            }
        )

    return recommendations


# ============================================================
# LOCAL AI-STYLE RECOMMENDATIONS
# ============================================================

def generate_ai_recommendations(scan_result):
    """
    Generate contextual recommendations locally.

    This mode does NOT use:
        - OpenAI API
        - external APIs
        - internet connection
        - API keys

    It is a local AI-style recommendation layer based on
    the scan data supplied by the toolkit.
    """

    if not isinstance(scan_result, dict):

        return {
            "success": False,
            "mode": "AI",
            "message": "Invalid scan result.",
            "recommendations": []
        }

    items = _collect_scan_items(scan_result)

    if not items:

        fallback = _generate_hardening_recommendations(
            scan_result,
            [],
            mode="AI"
        )

        return {
            "success": True,
            "mode": "AI",
            "message": (
                "The scan did not expose structured findings. "
                "General defensive hardening recommendations "
                "were generated instead."
            ),
            "overall_advice": [
                (
                    "Use the recommendations as defensive guidance "
                    "and verify important changes with a follow-up "
                    "authorized scan."
                )
            ],
            "recommendations": fallback
        }

    recommendations = []

    finding_names = []

    for item in items:

        name = _clean_text(item.get("name"))
        evidence = _clean_text(item.get("evidence"))
        severity = item.get("severity")

        if not name:
            continue

        name_lower = name.lower()
        evidence_lower = evidence.lower()

        finding_names.append(name_lower)

        rule = find_rule(name)

        if rule is None and evidence:
            rule = find_rule(evidence)

        # ----------------------------------------------------
        # Server / Information Disclosure
        # ----------------------------------------------------

        if (
            "server information" in name_lower
            or "information disclosure" in name_lower
            or (
                "server" in name_lower
                and "information" in name_lower
            )
        ):

            priority = severity or "Low"

            risk = (
                "Exposing server or technology information can help "
                "an attacker identify technologies and versions used "
                "by the application."
            )

            recommendation = (
                "Minimize unnecessary server information disclosure. "
                "Hide server version details where possible and review "
                "response headers for unnecessary technology information."
            )

        # ----------------------------------------------------
        # HTTP Methods
        # ----------------------------------------------------

        elif (
            "http method" in name_lower
            or "http methods" in name_lower
            or "methods" == name_lower
        ):

            priority = severity or "Medium"

            risk = (
                "Unnecessary HTTP methods can increase the available "
                "attack surface of a web application."
            )

            recommendation = (
                "Allow only HTTP methods required by the application. "
                "Disable unnecessary methods at the web server or "
                "application configuration level."
            )

        # ----------------------------------------------------
        # Directory Listing
        # ----------------------------------------------------

        elif "directory listing" in name_lower:

            priority = severity or "Medium"

            risk = (
                "Directory listing may expose files, folders, backups, "
                "or other resources that were not intended to be public."
            )

            recommendation = (
                "Disable directory indexing where it is not required. "
                "Restrict access to sensitive directories and verify "
                "that backup or internal files cannot be accessed directly."
            )

        # ----------------------------------------------------
        # Sensitive Paths
        # ----------------------------------------------------

        elif (
            "sensitive path" in name_lower
            or "sensitive paths" in name_lower
        ):

            priority = severity or "High"

            risk = (
                "Exposed administrative, configuration, backup, or "
                "internal paths may provide access to sensitive resources."
            )

            recommendation = (
                "Restrict access to sensitive paths. Remove unnecessary "
                "public exposure, apply authentication where required, "
                "and prevent direct access to configuration or backup "
                "resources."
            )

        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        elif (
            name_lower == "https"
            or "https" in name_lower
        ):

            priority = severity or "High"

            if (
                "not detected" in evidence_lower
                or "not enabled" in evidence_lower
                or "disabled" in evidence_lower
                or "missing" in evidence_lower
            ):

                risk = (
                    "The scanner indicates that HTTPS may not be "
                    "properly enabled or detected."
                )

                recommendation = (
                    "Enable HTTPS using a valid TLS certificate. "
                    "Redirect HTTP traffic to HTTPS and verify the "
                    "TLS configuration."
                )

            else:

                risk = (
                    "Transport security should be continuously "
                    "reviewed even when HTTPS is detected."
                )

                recommendation = (
                    "Keep HTTPS enabled and periodically review the "
                    "TLS configuration, certificate validity, and "
                    "secure protocol settings."
                )

        # ----------------------------------------------------
        # SSL / TLS
        # ----------------------------------------------------

        elif (
            "ssl" in name_lower
            or "tls" in name_lower
        ):

            priority = severity or "High"

            risk = (
                "Weak or incorrectly configured TLS settings may "
                "reduce the security of encrypted communication."
            )

            recommendation = (
                "Review the TLS configuration. Use currently "
                "supported secure protocols, valid certificates, "
                "and disable obsolete or insecure configurations."
            )

        # ----------------------------------------------------
        # Security Headers
        # ----------------------------------------------------

        elif (
            "security header" in name_lower
            or "missing header" in name_lower
        ):

            priority = severity or "Medium"

            risk = (
                "Missing or weak HTTP security headers can reduce "
                "browser-side security protections."
            )

            recommendation = (
                "Add appropriate security headers based on the "
                "application's requirements. Review headers such as "
                "Content-Security-Policy, X-Content-Type-Options, "
                "Referrer-Policy, and frame protection."
            )

        # ----------------------------------------------------
        # Generic Finding
        # ----------------------------------------------------

        else:

            if rule:

                priority = severity or rule.get(
                    "severity",
                    "Medium"
                )

                risk = (
                    "The scanner identified a condition that should "
                    "be reviewed from a security perspective."
                )

                recommendation = rule.get(
                    "recommendation",
                    (
                        "Review the finding and reduce unnecessary "
                        "exposure where possible."
                    )
                )

            else:

                priority = severity or "Medium"

                risk = (
                    "The scan identified a condition that may "
                    "increase the application's security exposure."
                )

                recommendation = (
                    "Review the finding manually, verify whether "
                    "the exposure is required, and apply a "
                    "minimum-exposure or least-privilege configuration "
                    "where appropriate."
                )

        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        if evidence:

            evidence_text = (
                f"The scanner provided the following evidence: "
                f"{evidence}"
            )

        else:

            evidence_text = (
                "No additional evidence was provided by the scanner."
            )

        recommendations.append(
            {
                "finding": name,
                "severity": priority,
                "risk": risk,
                "evidence": evidence_text,
                "recommendation": recommendation,
                "mode": "AI"
            }
        )

    # --------------------------------------------------------
    # If extracted data exists but no useful recommendation
    # was created, provide hardening guidance.
    # --------------------------------------------------------

    if not recommendations:

        recommendations = _generate_hardening_recommendations(
            scan_result,
            items,
            mode="AI"
        )

    # --------------------------------------------------------
    # Overall advice
    # --------------------------------------------------------

    overall_advice = []

    combined_names = " ".join(finding_names)

    if (
        "https" in combined_names
        or "ssl" in combined_names
        or "tls" in combined_names
    ):

        overall_advice.append(
            "Prioritize transport security and periodically verify "
            "HTTPS/TLS configuration."
        )

    if (
        "sensitive path" in combined_names
        or "directory listing" in combined_names
    ):

        overall_advice.append(
            "Review public resource exposure and ensure sensitive "
            "files and directories are not unnecessarily accessible."
        )

    if (
        "security header" in combined_names
        or "missing header" in combined_names
    ):

        overall_advice.append(
            "After applying header changes, perform another "
            "authorized scan to verify the expected security headers."
        )

    if (
        "http method" in combined_names
        or "methods" in combined_names
    ):

        overall_advice.append(
            "Keep the HTTP method surface as small as practical "
            "and allow only methods required by the application."
        )

    if not overall_advice:

        overall_advice.append(
            "Use the recommendations as defensive hardening guidance "
            "and perform a follow-up authorized scan after making "
            "security changes."
        )

    return {
        "success": True,
        "mode": "AI",
        "message": (
            "Local AI-style security analysis completed successfully."
        ),
        "overall_advice": overall_advice,
        "recommendations": recommendations
    }


# ============================================================
# MAIN FUNCTION
# ============================================================

def generate_recommendations(scan_result, mode="normal"):
    """
    Generate recommendations using the selected mode.

    mode:
        normal
        ai
    """

    selected_mode = str(mode).lower().strip()

    if selected_mode == "normal":

        return generate_normal_recommendations(
            scan_result
        )

    if selected_mode == "ai":

        return generate_ai_recommendations(
            scan_result
        )

    return {
        "success": False,
        "mode": selected_mode,
        "message": (
            "Invalid recommendation mode. "
            "Use 'normal' or 'ai'."
        ),
        "recommendations": []
    }


# ============================================================
# FORMAT RESULT FOR GUI
# ============================================================

def format_recommendations(recommendations):
    """
    Convert recommendation data into GUI-friendly text.
    """

    if recommendations is None:

        return "No recommendation data was returned."

    # --------------------------------------------------------
    # Dictionary result
    # --------------------------------------------------------

    if isinstance(recommendations, dict):

        output = []

        message = recommendations.get(
            "message",
            ""
        )

        if message:

            output.append(message)
            output.append("")

        overall_advice = recommendations.get(
            "overall_advice",
            []
        )

        if overall_advice:

            output.append(
                "OVERALL ADVICE"
            )

            for advice in overall_advice:

                output.append(
                    f"• {advice}"
                )

            output.append(
                "-" * 60
            )

        recommendation_list = recommendations.get(
            "recommendations",
            []
        )

        if not recommendation_list:

            output.append(
                "General security hardening is recommended."
            )

            return "\n".join(output)

        recommendations = recommendation_list

        if not recommendations:

            return "\n".join(output)

    # --------------------------------------------------------
    # List result
    # --------------------------------------------------------

    if not isinstance(recommendations, list):

        return str(recommendations)

    if not recommendations:

        return (
            "General security hardening is recommended."
        )

    output = []

    for number, item in enumerate(
        recommendations,
        start=1
    ):

        if not isinstance(item, dict):

            output.append(
                f"{number}. {item}"
            )

            output.append(
                "-" * 60
            )

            continue

        finding = item.get(
            "finding",
            "Unknown Finding"
        )

        severity = item.get(
            "severity",
            "Unknown"
        )

        output.append(
            f"{number}. {finding}"
        )

        output.append(
            f"Severity: {severity}"
        )

        risk = item.get(
            "risk",
            ""
        )

        if risk:

            output.append(
                f"Risk: {risk}"
            )

        evidence = item.get(
            "evidence",
            ""
        )

        if evidence:

            output.append(
                f"Evidence: {evidence}"
            )

        recommendation = item.get(
            "recommendation",
            "No recommendation available."
        )

        output.append(
            "Recommendation: "
            + str(recommendation)
        )

        output.append(
            f"Mode: {item.get('mode', 'Normal')}"
        )

        output.append(
            "-" * 60
        )

    return "\n".join(output)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_scan = {
        "scan_type": "Vulnerability Assessment",
        "target": "https://example.com",

        "findings": [
            {
                "name": "Directory Listing",
                "severity": "Medium",
                "evidence": "/uploads/"
            },
            {
                "name": "HTTPS",
                "severity": "High",
                "evidence": "HTTPS not detected"
            },
            {
                "name": "Server Information Disclosure",
                "severity": "Low",
                "evidence": "Apache/2.4.58"
            }
        ]
    }

    print("=" * 60)
    print("NORMAL RECOMMENDATIONS")
    print("=" * 60)

    normal_result = generate_recommendations(
        test_scan,
        "normal"
    )

    print(
        format_recommendations(
            normal_result
        )
    )

    print()
    print("=" * 60)
    print("AI RECOMMENDATIONS")
    print("=" * 60)

    ai_result = generate_recommendations(
        test_scan,
        "ai"
    )

    print(
        format_recommendations(
            ai_result
        )
    )

    print()
    print("=" * 60)
    print("NESTED RESULT TEST")
    print("=" * 60)

    nested_test = {
        "Reconnaissance": {
            "target": "https://example.com",
            "server_information": "Apache",
            "http_methods": "GET, POST"
        },

        "Security Analysis": {
            "security_headers": "Some headers detected"
        },

        "Vulnerability Assessment": {
            "directory_listing": "Not detected",
            "sensitive_paths": "No sensitive paths found",
            "https": "HTTPS detected"
        }
    }

    nested_result = generate_recommendations(
        nested_test,
        "normal"
    )

    print(
        format_recommendations(
            nested_result
        )
    )
