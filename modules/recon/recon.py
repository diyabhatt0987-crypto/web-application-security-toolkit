
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


# ============================================================
# RECONNAISSANCE SCAN PROFILES
# ============================================================

QUICK_CHECKS = {
    "basic_info",
    "page_title",
    "technology_hints",
}

STANDARD_CHECKS = {
    "basic_info",
    "page_title",
    "links",
    "forms",
    "response_headers",
    "cookies",
    "technology_hints",
}

DEEP_CHECKS = STANDARD_CHECKS | {
    "meta_info",
    "robots_txt",
    "sitemap_xml",
}

AVAILABLE_CHECKS = {
    "basic_info",
    "page_title",
    "links",
    "forms",
    "response_headers",
    "cookies",
    "technology_hints",
    "meta_info",
    "robots_txt",
    "sitemap_xml",
}


def get_origin(url):
    """Return the scheme, hostname and port of a URL."""
    parsed = urlparse(url)

    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port
    )


def fetch_same_origin_resource(base_url, resource_path):
    """
    Make one non-invasive GET request to a resource on the same origin.
    Redirects are disabled to avoid following links to another host.
    """

    resource_url = urljoin(base_url, resource_path)

    if get_origin(resource_url) != get_origin(base_url):
        return {
            "URL": resource_url,
            "Status Code": "Skipped",
            "Content Preview": "",
            "Note": "Resource is outside the target origin."
        }

    try:
        response = requests.get(
            resource_url,
            timeout=5,
            headers={
                "User-Agent": "WebApp-Security-Toolkit/1.0"
            },
            allow_redirects=False,
            stream=True
        )

        try:
            status_code = response.status_code
            content_type = response.headers.get(
                "Content-Type", ""
            )

            if status_code in (301, 302, 303, 307, 308):
                return {
                    "URL": resource_url,
                    "Status Code": status_code,
                    "Content Preview": "",
                    "Note": "Redirect detected; not followed."
                }

            # Read only a bounded preview instead of downloading
            # an entire potentially large resource.
            chunks = []
            total_bytes = 0
            max_bytes = 65536

            for chunk in response.iter_content(
                chunk_size=4096
            ):
                if not chunk:
                    continue

                remaining = max_bytes - total_bytes

                if remaining <= 0:
                    break

                chunk = chunk[:remaining]
                chunks.append(chunk)
                total_bytes += len(chunk)

                if total_bytes >= max_bytes:
                    break

            raw_content = b"".join(chunks)

            encoding = response.encoding or "utf-8"

            content_preview = raw_content.decode(
                encoding,
                errors="replace"
            )[:2000]

            return {
                "URL": resource_url,
                "Status Code": status_code,
                "Content Type": content_type,
                "Content Preview": content_preview,
                "Note": (
                    "Preview limited to 64 KB of response data."
                    if total_bytes >= max_bytes
                    else ""
                )
            }

        finally:
            response.close()

    except requests.exceptions.RequestException as error:
        return {
            "URL": resource_url,
            "Status Code": "Unavailable",
            "Content Preview": "",
            "Note": str(error)
        }


# ============================================================
# MAIN RECONNAISSANCE FUNCTION
# ============================================================

def scan_target(target_url, profile="Standard",
                selected_checks=None):

    print("\n" + "=" * 60)
    print("RECONNAISSANCE")
    print("=" * 60)

    # --------------------------------------------------------
    # Validate target URL
    # --------------------------------------------------------

    target_url = (target_url or "").strip()

    if not target_url:
        print("\nError: Target URL is empty.")
        return None

    parsed_target = urlparse(target_url)

    if (
        parsed_target.scheme.lower() not in ("http", "https")
        or not parsed_target.hostname
    ):
        print(
            "\nError: Enter a valid HTTP or HTTPS URL, "
            "including its scheme."
        )
        return None

    # --------------------------------------------------------
    # Choose scan profile
    # --------------------------------------------------------

    profile = (profile or "Standard").strip().title()

    profile_checks = {
        "Quick": QUICK_CHECKS,
        "Standard": STANDARD_CHECKS,
        "Deep": DEEP_CHECKS,
    }

    if profile == "Custom":
        if selected_checks is None:
            print(
                "\nError: Custom profile requires selected_checks."
            )
            return None

        checks = set(selected_checks) & AVAILABLE_CHECKS

        if not checks:
            print(
                "\nError: Select at least one valid "
                "reconnaissance check."
            )
            return None

    elif profile in profile_checks:
        checks = set(profile_checks[profile])

    else:
        print(
            "\nError: Unknown profile. Choose Quick, Standard, "
            "Deep or Custom."
        )
        return None

    # Basic target information is required for every profile.
    checks.add("basic_info")

    print(f"\nScan Profile: {profile}")
    print("Checks selected:", ", ".join(sorted(checks)))

    # --------------------------------------------------------
    # Initialize stable result structure
    # --------------------------------------------------------

    results = {
        "Target URL": target_url,
        "Final URL": "",
        "Status Code": "",
        "Page Title": "Not Checked",
        "Links": [],
        "Forms": [],
        "Response Headers": {},
        "Cookies": [],
        "Technology Hints": [],
        "Server": "Not Checked",
        "X-Powered-By": "Not Checked",
        "Meta Information": [],
        "Robots.txt": {},
        "Sitemap.xml": {},
        "Scan Profile": profile,
        "Checks Performed": [],
    }

    # --------------------------------------------------------
    # Send initial GET request
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
        # ----------------------------------------------------
        # Basic Information
        # ----------------------------------------------------

        results["Final URL"] = response.url
        results["Status Code"] = response.status_code

        print(f"\nTarget URL: {target_url}")
        print(f"Final URL: {response.url}")
        print(f"Status Code: {response.status_code}")

        results["Checks Performed"].append("basic_info")

        # Parse HTML only when an HTML response is returned.
        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        is_html = (
            "text/html" in content_type
            or "application/xhtml+xml" in content_type
        )

        soup = (
            BeautifulSoup(response.text, "html.parser")
            if is_html
            else BeautifulSoup("", "html.parser")
        )

        # ----------------------------------------------------
        # Page Title
        # ----------------------------------------------------

        if "page_title" in checks:
            title_tag = soup.find("title")

            title = (
                title_tag.get_text(strip=True)
                if title_tag
                else "Not Found"
            )

            results["Page Title"] = title
            results["Checks Performed"].append("page_title")

            print(f"\nPage Title: {title}")

        # ----------------------------------------------------
        # Links
        # ----------------------------------------------------

        if "links" in checks:
            links = set()

            for link in soup.find_all("a", href=True):
                href = link.get("href", "").strip()

                if not href:
                    continue

                absolute_url = urljoin(response.url, href)
                links.add(absolute_url)

            results["Links"] = sorted(links)
            results["Checks Performed"].append("links")

            print("\n[+] Links Found:", len(links))

            for link in sorted(links):
                print("   ", link)

        # ----------------------------------------------------
        # Forms
        # ----------------------------------------------------

        if "forms" in checks:
            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "GET").upper()

                if method not in {
                    "GET", "POST", "PUT", "PATCH",
                    "DELETE", "OPTIONS", "HEAD"
                }:
                    method = "UNKNOWN"

                action = urljoin(
                    response.url,
                    form.get("action", "")
                )

                form_data = {
                    "method": method,
                    "action": action
                }

                results["Forms"].append(form_data)

            results["Checks Performed"].append("forms")

            print("\n[+] Forms Found:", len(forms))

            for form in results["Forms"]:
                print("   Method:", form["method"])
                print("   Action:", form["action"])

        # ----------------------------------------------------
        # Response Headers
        # ----------------------------------------------------

        if "response_headers" in checks:
            print("\n[+] Response Headers:")

            for header, value in response.headers.items():
                if header.lower() in {
                    "set-cookie",
                    "authorization",
                    "proxy-authorization"
                }:
                    safe_value = "[REDACTED]"
                else:
                    safe_value = value

                results["Response Headers"][header] = safe_value

                print(f"   {header}: {safe_value}")

            results["Checks Performed"].append(
                "response_headers"
            )

        # ----------------------------------------------------
        # Cookies
        # ----------------------------------------------------

        if "cookies" in checks:
            print("\n[+] Cookies:")

            for cookie in response.cookies:
                cookie_attributes = (
                    getattr(cookie, "_rest", {}) or {}
                )

                httponly = any(
                    key.lower() == "httponly"
                    for key in cookie_attributes
                )

                samesite = next(
                    (
                        value
                        for key, value in cookie_attributes.items()
                        if key.lower() == "samesite"
                    ),
                    "Not specified"
                )

                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": httponly,
                    "samesite": samesite
                }

                results["Cookies"].append(cookie_info)

                print(
                    f"   {cookie.name} | "
                    f"Secure={cookie.secure} | "
                    f"HttpOnly={httponly} | "
                    f"SameSite={samesite}"
                )

            results["Checks Performed"].append("cookies")

        # ----------------------------------------------------
        # Technology Hints
        # ----------------------------------------------------

        if "technology_hints" in checks:
            technology_hints = []

            server = response.headers.get("Server")
            powered_by = response.headers.get("X-Powered-By")

            if server:
                technology_hints.append(
                    f"Server: {server}"
                )

            if powered_by:
                technology_hints.append(
                    f"X-Powered-By: {powered_by}"
                )

            results["Technology Hints"] = technology_hints
            results["Server"] = server or "Not disclosed"
            results["X-Powered-By"] = (
                powered_by or "Not disclosed"
            )

            results["Checks Performed"].append(
                "technology_hints"
            )

            print("\n[+] Technology Hints:")

            if technology_hints:
                for technology in technology_hints:
                    print("   ", technology)
            else:
                print("    No obvious technology hints found")

        # ----------------------------------------------------
        # Deep Check: HTML Meta Information
        # ----------------------------------------------------

        if "meta_info" in checks:
            meta_information = []

            for meta in soup.find_all("meta"):
                name = (
                    meta.get("name")
                    or meta.get("property")
                    or meta.get("http-equiv")
                )

                content = meta.get("content")

                if name and content:
                    meta_information.append({
                        "name": name,
                        "content": content[:500]
                    })

            results["Meta Information"] = meta_information
            results["Checks Performed"].append("meta_info")

            print(
                "\n[+] Meta Information Found:",
                len(meta_information)
            )

            for item in meta_information:
                print(
                    f"   {item['name']}: {item['content']}"
                )

        # ----------------------------------------------------
        # Deep Check: robots.txt
        # ----------------------------------------------------

        if "robots_txt" in checks:
            robots_result = fetch_same_origin_resource(
                response.url,
                "/robots.txt"
            )

            results["Robots.txt"] = robots_result
            results["Checks Performed"].append("robots_txt")

            print("\n[+] robots.txt")
            print("   Status:", robots_result["Status Code"])

            preview = robots_result.get(
                "Content Preview", ""
            )

            if preview:
                print("   Preview:")
                print(preview[:500])

            if robots_result.get("Note"):
                print("   Note:", robots_result["Note"])

        # ----------------------------------------------------
        # Deep Check: sitemap.xml
        # ----------------------------------------------------

        if "sitemap_xml" in checks:
            sitemap_result = fetch_same_origin_resource(
                response.url,
                "/sitemap.xml"
            )

            results["Sitemap.xml"] = sitemap_result
            results["Checks Performed"].append("sitemap_xml")

            print("\n[+] sitemap.xml")
            print("   Status:", sitemap_result["Status Code"])

            if sitemap_result.get("Note"):
                print("   Note:", sitemap_result["Note"])

        # ----------------------------------------------------
        # Return Results
        # ----------------------------------------------------

        print("\n[+] Reconnaissance completed.")
        print("Profile:", profile)
        print(
            "Checks performed:",
            ", ".join(results["Checks Performed"])
        )

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
            "4": "Custom"
        }

        profile = profile_map.get(choice)

        if not profile:
            print("Invalid choice.")
        else:
            selected_checks = None

            if profile == "Custom":
                check_names = sorted(
                    AVAILABLE_CHECKS - {"basic_info"}
                )

                print("\nAvailable checks:")

                for index, check_name in enumerate(
                    check_names, start=1
                ):
                    print(f"{index}. {check_name}")

                selected_input = input(
                    "Enter check numbers separated by commas: "
                ).strip()

                try:
                    selected_indexes = {
                        int(value.strip())
                        for value in selected_input.split(",")
                        if value.strip()
                    }

                    if any(
                        index < 1 or index > len(check_names)
                        for index in selected_indexes
                    ):
                        raise ValueError

                    selected_checks = [
                        check_names[index - 1]
                        for index in selected_indexes
                    ]

                except ValueError:
                    print("Invalid selection.")
                    raise SystemExit(1)

            scan_target(
                target_url,
                profile=profile,
                selected_checks=selected_checks
            )
