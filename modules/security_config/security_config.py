
import requests
from urllib.parse import urlparse


# ============================================================
# SECURITY CONFIGURATION SCAN PROFILES
# ============================================================

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Strict-Transport-Security": "HSTS",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}

AVAILABLE_CHECKS = {
    "https",
    "security_headers",
    "cookie_security",
    "server_information",
}


PROFILE_CHECKS = {
    "Quick": {
        "https",
        "security_headers",
    },
    "Standard": {
        "https",
        "security_headers",
        "cookie_security",
        "server_information",
    },
    "Deep": {
        "https",
        "security_headers",
        "cookie_security",
        "server_information",
    },
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def validate_target_url(target_url):
    """Validate the URL before making an HTTP request."""

    target_url = (target_url or "").strip()
    parsed = urlparse(target_url)

    if (
        parsed.scheme.lower() not in ("http", "https")
        or not parsed.hostname
    ):
        return None

    try:
        # Accessing port can raise ValueError for invalid ports.
        _ = parsed.port
    except ValueError:
        return None

    return target_url


def get_cookie_attributes(cookie):
    """Read cookie security attributes safely."""

    attributes = getattr(cookie, "_rest", {}) or {}

    httponly = any(
        key.lower() == "httponly"
        for key in attributes
    )

    samesite = next(
        (
            value
            for key, value in attributes.items()
            if key.lower() == "samesite"
        ),
        "Not specified"
    )

    return httponly, samesite


# ============================================================
# MAIN SECURITY CONFIGURATION FUNCTION
# ============================================================

def check_security_config(
    target_url,
    profile="Standard",
    selected_checks=None
):
    """
    Analyze HTTP security configuration.

    Existing usage remains valid:
        check_security_config(target_url)

    Profile-based usage:
        check_security_config(target_url, profile="Quick")
        check_security_config(target_url, profile="Deep")

    Custom usage:
        check_security_config(
            target_url,
            profile="Custom",
            selected_checks=["https", "cookie_security"]
        )
    """

    print("\n" + "=" * 60)
    print("SECURITY CONFIGURATION ANALYSIS")
    print("=" * 60)

    target_url = validate_target_url(target_url)

    if not target_url:
        print(
            "\nError: Enter a valid HTTP or HTTPS URL."
        )
        return None

    profile = (profile or "Standard").strip().title()

    if profile == "Custom":
        if selected_checks is None:
            print(
                "\nError: Custom profile requires selected_checks."
            )
            return None

        checks = set(selected_checks) & AVAILABLE_CHECKS

        if not checks:
            print(
                "\nError: Select at least one valid security check."
            )
            return None

    elif profile in PROFILE_CHECKS:
        checks = set(PROFILE_CHECKS[profile])

    else:
        print(
            "\nError: Unknown profile. Choose Quick, Standard, "
            "Deep or Custom."
        )
        return None

    # Deep currently includes all checks implemented in this
    # module. It does not perform intrusive testing.
    print(f"\nScan Profile: {profile}")
    print("Checks selected:", ", ".join(sorted(checks)))

    results = {
        "HTTPS": "Not Checked",
        "Security Headers": {},
        "Cookie Security": [],
        "Server": "Not Checked",
        "X-Powered-By": "Not Checked",
        "Scan Profile": profile,
        "Checks Performed": [],
    }

    # --------------------------------------------------------
    # Send a single GET request
    # --------------------------------------------------------

    try:
        response = requests.get(
            target_url,
            timeout=10,
            headers={
                "User-Agent": "WebApp-Security-Toolkit/1.0"
            },
            allow_redirects=True
        )

    except requests.exceptions.RequestException as error:
        print("\nError:", error)
        return None

    try:
        print(f"\nFinal URL: {response.url}")
        print(f"Status Code: {response.status_code}")

        # ----------------------------------------------------
        # HTTPS Check
        # ----------------------------------------------------

        if "https" in checks:
            print("\n[+] HTTPS Check:")

            if response.url.lower().startswith("https://"):
                results["HTTPS"] = "PASS - HTTPS is enabled"
                print("    [PASS] HTTPS is enabled")
            else:
                results["HTTPS"] = (
                    "WARNING - HTTPS is not enabled"
                )
                print("    [WARNING] HTTPS is not enabled")

            results["Checks Performed"].append("https")

        # ----------------------------------------------------
        # Security Headers
        # ----------------------------------------------------

        if "security_headers" in checks:
            print("\n[+] Security Headers:")

            for header, display_name in SECURITY_HEADERS.items():
                value = response.headers.get(header)

                if value:
                    results["Security Headers"][display_name] = (
                        f"PASS - {value}"
                    )
                    print(f"    [PASS] {display_name}")
                else:
                    results["Security Headers"][display_name] = (
                        "MISSING"
                    )
                    print(f"    [MISSING] {display_name}")

            results["Checks Performed"].append(
                "security_headers"
            )

        # ----------------------------------------------------
        # Cookie Security
        # ----------------------------------------------------

        if "cookie_security" in checks:
            print("\n[+] Cookie Security:")

            if response.cookies:
                for cookie in response.cookies:
                    httponly, samesite = get_cookie_attributes(
                        cookie
                    )

                    cookie_info = {
                        "Name": cookie.name,
                        "Secure": cookie.secure,
                        "HttpOnly": httponly,
                        "SameSite": samesite,
                    }

                    results["Cookie Security"].append(
                        cookie_info
                    )

                    print(
                        f"    {cookie.name} | "
                        f"Secure={cookie.secure} | "
                        f"HttpOnly={httponly} | "
                        f"SameSite={samesite}"
                    )
            else:
                print("    No cookies detected in this response")

            results["Checks Performed"].append(
                "cookie_security"
            )

        # ----------------------------------------------------
        # Server Information
        # ----------------------------------------------------

        if "server_information" in checks:
            print("\n[+] Server Information:")

            server = response.headers.get("Server")
            powered_by = response.headers.get("X-Powered-By")

            results["Server"] = server or "Not disclosed"
            results["X-Powered-By"] = (
                powered_by or "Not disclosed"
            )

            if server:
                print(f"    Server: {server}")
            else:
                print("    Server: Not disclosed")

            if powered_by:
                print(
                    f"    [INFO] X-Powered-By disclosed: "
                    f"{powered_by}"
                )
            else:
                print(
                    "    [PASS] X-Powered-By not disclosed"
                )

            results["Checks Performed"].append(
                "server_information"
            )

        print("\n[+] Security configuration analysis completed.")
        print("Profile:", profile)

        return results

    finally:
        response.close()


# ============================================================
# STANDALONE EXECUTION
# ============================================================

if __name__ == "__main__":

    target_url = input(
        "Enter authorized target URL (http:// or https://): "
    ).strip()

    if not target_url:
        print("Please enter a valid URL.")
    else:
        print("\nSelect scan profile:")
        print("1. Quick")
        print("2. Standard")
        print("3. Deep")
        print("4. Custom")

        choice = input("Enter choice (1-4): ").strip()

        profile_map = {
            "1": "Quick",
            "2": "Standard",
            "3": "Deep",
            "4": "Custom",
        }

        profile = profile_map.get(choice)

        if not profile:
            print("Invalid choice.")
        else:
            selected_checks = None

            if profile == "Custom":
                check_names = sorted(AVAILABLE_CHECKS)

                print("\nAvailable checks:")

                for index, name in enumerate(
                    check_names, start=1
                ):
                    print(f"{index}. {name}")

                selected_input = input(
                    "Enter check numbers separated by commas: "
                ).strip()

                try:
                    indexes = {
                        int(value.strip())
                        for value in selected_input.split(",")
                        if value.strip()
                    }

                    if any(
                        index < 1 or index > len(check_names)
                        for index in indexes
                    ):
                        raise ValueError

                    selected_checks = [
                        check_names[index - 1]
                        for index in indexes
                    ]

                except ValueError:
                    print("Invalid selection.")
                    raise SystemExit(1)

            check_security_config(
                target_url,
                profile=profile,
                selected_checks=selected_checks
            )
