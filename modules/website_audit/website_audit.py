"""A small, read-only crawl for authorized website reviews.

The crawler follows only same-origin HTML links, obeys robots.txt when it
can be read, and never submits forms or sends test payloads.
"""

from collections import deque
from datetime import datetime, timezone
from time import monotonic, sleep
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


USER_AGENT = "WebApp-Security-Toolkit/1.0"
REQUEST_TIMEOUT = 8
MAX_PAGES = 25
MAX_DEPTH = 2
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 512 * 1024
MAX_BODY_READ_SECONDS = 10
REQUEST_DELAY_SECONDS = 0.2
MAX_LINKS_PER_PAGE = 200

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)


def _origin(url):
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        port or default_port,
    )


def _validate_target(target_url):
    target_url = (target_url or "").strip()
    try:
        parsed = urlparse(target_url)
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS website URL.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS website URL.")
    if any(char.isspace() for char in target_url):
        raise ValueError("The website URL cannot contain spaces.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc
    return _canonical_url(target_url)


def _canonical_url(url):
    """Drop fragments and query strings so crawl scope stays predictable."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
    return urldefrag(normalized)[0]


def _read_limited_body(response, limit=MAX_RESPONSE_BYTES):
    body = bytearray()
    started = monotonic()
    truncated = False
    for chunk in response.iter_content(chunk_size=16 * 1024):
        if monotonic() - started >= MAX_BODY_READ_SECONDS:
            truncated = True
            break
        if not chunk:
            continue
        remaining = limit - len(body)
        if remaining <= 0:
            break
        body.extend(chunk[:remaining])
        if len(body) >= limit:
            truncated = True
            break
    encoding = response.encoding or "utf-8"
    try:
        text = bytes(body).decode(encoding, errors="replace")
    except LookupError:
        text = bytes(body).decode("utf-8", errors="replace")
    return text, truncated


def _request_in_scope(session, url, target_origin):
    """Request a URL while refusing to follow redirects off the target origin."""
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(
            current_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return None, current_url, "Redirect did not include a destination."
            try:
                next_url = _canonical_url(urljoin(current_url, location))
                parsed_next = urlparse(next_url)
            except ValueError:
                return None, current_url, "Malformed redirect destination was not followed."
            if parsed_next.username or parsed_next.password:
                return None, next_url, "Redirect with embedded credentials was not followed."
            if _origin(next_url) != target_origin:
                return None, next_url, "Cross-origin redirect was not followed."
            current_url = next_url
            continue
        return response, current_url, ""
    return None, current_url, "Redirect limit reached."


def _add_finding(findings, status, title, details, url=""):
    severity = {
        "WARNING": "Medium",
        "ERROR": "High",
        "INFO": "Informational",
        "PASS": "Low",
    }.get(status, "Informational")
    findings.append({
        "status": status,
        "severity": severity,
        "title": title,
        "details": details,
        "url": url,
    })


def _robots_policy(session, start_url, origin, warnings):
    robots_url = urljoin(start_url, "/robots.txt")
    parser = RobotFileParser()
    parser.set_url(robots_url)
    try:
        response, final_url, redirect_note = _request_in_scope(
            session, robots_url, origin
        )
        if response is None:
            warnings.append(f"robots.txt could not be read: {redirect_note}")
            parser.parse([])
        else:
            try:
                body, truncated = _read_limited_body(response, 64 * 1024)
                parser.parse(body.splitlines())
                if truncated:
                    warnings.append("robots.txt reached its size or 10-second read limit.")
            finally:
                response.close()
    except requests.RequestException as exc:
        warnings.append(f"robots.txt could not be read: {exc}")
        parser.parse([])
    return parser


def crawl_website(
    target_url,
    max_pages=MAX_PAGES,
    max_depth=MAX_DEPTH,
    progress_callback=None,
):
    """Crawl a small number of same-origin pages and review public forms."""
    start_url = _validate_target(target_url)
    origin = _origin(start_url)
    max_pages = max(1, min(int(max_pages), 100))
    max_depth = max(0, min(int(max_depth), 5))

    results = {
        "Target URL": start_url,
        "Scan Time (UTC)": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "Scope": {
            "Same-Origin Only": True,
            "Maximum Pages": max_pages,
            "Maximum Link Depth": max_depth,
            "Query Parameters Followed": False,
            "Fragments Followed": False,
            "Forms Submitted": False,
            "Payloads Sent": False,
        },
        "Pages": [],
        "Findings": [],
        "Warnings": [],
        "Summary": {},
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
    })
    session.verify = True
    try:
        robots = _robots_policy(session, start_url, origin, results["Warnings"])
        queue = deque([(start_url, 0)])
        visited = set()
        queued = {start_url}
        missing_headers = set()
        pages_with_html = 0

        while queue and len(results["Pages"]) < max_pages:
            requested_url, depth = queue.popleft()
            canonical = _canonical_url(requested_url)
            if canonical in visited:
                continue
            visited.add(canonical)

            if not robots.can_fetch(USER_AGENT, canonical):
                _add_finding(
                    results["Findings"], "INFO", "Page skipped by robots.txt",
                    "The path was not crawled because robots.txt disallows it.", canonical,
                )
                continue

            if progress_callback:
                progress_callback(len(results["Pages"]) + 1, max_pages, canonical)

            if results["Pages"]:
                sleep(REQUEST_DELAY_SECONDS)

            page = {
                "URL": canonical,
                "Depth": depth,
                "Status Code": None,
                "Content Type": "",
                "Title": "",
                "Links Found": 0,
                "Forms Found": 0,
            }
            try:
                response, final_url, redirect_note = _request_in_scope(
                    session, canonical, origin
                )
                if response is None:
                    page["Note"] = redirect_note
                    _add_finding(
                        results["Findings"], "INFO", "Page was not followed",
                        redirect_note, canonical,
                    )
                    results["Pages"].append(page)
                    continue

                try:
                    page["URL"] = final_url
                    page["Status Code"] = response.status_code
                    content_type = response.headers.get("Content-Type", "")
                    page["Content Type"] = content_type
                    for header in SECURITY_HEADERS:
                        if not response.headers.get(header):
                            missing_headers.add(header)

                    if response.status_code >= 500:
                        _add_finding(
                            results["Findings"], "WARNING", "Server error response",
                            f"The page returned HTTP {response.status_code}.", final_url,
                        )
                    elif response.status_code >= 400:
                        _add_finding(
                            results["Findings"], "INFO", "Page returned an error status",
                            f"The page returned HTTP {response.status_code}.", final_url,
                        )

                    is_html = any(
                        value in content_type.lower()
                        for value in ("text/html", "application/xhtml+xml")
                    )
                    if is_html and response.status_code < 400:
                        html, truncated = _read_limited_body(response)
                        pages_with_html += 1
                        if truncated:
                            page["Note"] = "HTML read reached its 512 KB or 10-second limit."
                        soup = BeautifulSoup(html, "html.parser")
                        title = soup.title.get_text(" ", strip=True) if soup.title else ""
                        page["Title"] = title[:200]

                        links = set()
                        for anchor in soup.find_all("a", href=True):
                            href = anchor.get("href", "").strip()
                            if not href or href.lower().startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                                continue
                            try:
                                absolute = _canonical_url(urljoin(final_url, href))
                                parsed_link = urlparse(absolute)
                            except ValueError:
                                continue
                            if (
                                len(absolute) > 2048
                                or parsed_link.username
                                or parsed_link.password
                                or _origin(absolute) != origin
                            ):
                                continue
                            links.add(absolute)
                            if len(links) >= MAX_LINKS_PER_PAGE:
                                break

                        page["Links Found"] = len(links)
                        if depth < max_depth:
                            for link in sorted(links):
                                if link not in visited:
                                    if link not in queued:
                                        queue.append((link, depth + 1))
                                        queued.add(link)

                        forms = soup.find_all("form")
                        page["Forms Found"] = len(forms)
                        for index, form in enumerate(forms, start=1):
                            method = (form.get("method") or "get").strip().upper()
                            raw_action = (form.get("action") or "").strip()
                            try:
                                action = _canonical_url(urljoin(final_url, raw_action or final_url))
                                parsed_action = urlparse(action)
                            except ValueError:
                                action = ""
                                parsed_action = None
                            password_fields = form.find_all("input", attrs={"type": lambda value: (value or "").lower() == "password"})
                            hidden_names = {
                                (field.get("name") or "").lower()
                                for field in form.find_all("input", attrs={"type": lambda value: (value or "").lower() == "hidden"})
                            }
                            has_csrf_hint = any(
                                any(token in name for token in ("csrf", "xsrf", "authenticity", "requesttoken"))
                                for name in hidden_names
                            )
                            form_title = f"Form {index} review"

                            if (
                                not action
                                or _origin(action) != origin
                                or (parsed_action and (parsed_action.username or parsed_action.password))
                            ):
                                _add_finding(
                                    results["Findings"], "WARNING", f"{form_title}: external destination",
                                    "The form submits to a different origin. Confirm that this is intentional.", final_url,
                                )
                            if password_fields and (
                                urlparse(final_url).scheme.lower() != "https"
                                or urlparse(action).scheme.lower() != "https"
                            ):
                                _add_finding(
                                    results["Findings"], "WARNING", f"{form_title}: password sent over HTTP",
                                    "The form page or its destination uses HTTP. Do not enter real credentials until reviewed.", final_url,
                                )
                            if password_fields and method == "GET":
                                _add_finding(
                                    results["Findings"], "WARNING", f"{form_title}: password form uses GET",
                                    "GET form values can appear in URLs, browser history, and server logs.", final_url,
                                )
                            if method in {"POST", "PUT", "PATCH", "DELETE"} and not has_csrf_hint:
                                _add_finding(
                                    results["Findings"], "INFO", f"{form_title}: review CSRF protection",
                                    "No common hidden CSRF-token field name was detected. Protection may be implemented elsewhere; verify manually.", final_url,
                                )
                            _add_finding(
                                results["Findings"], "INFO", form_title,
                                f"Observed a {method} form with {len(form.find_all(['input', 'select', 'textarea']))} fields; the form was not submitted.",
                                final_url,
                            )
                finally:
                    response.close()
            except requests.RequestException as exc:
                page["Note"] = str(exc)
                _add_finding(
                    results["Findings"], "INFO", "Page could not be read",
                    str(exc), canonical,
                )
            results["Pages"].append(page)

        if queue:
            results["Warnings"].append(
                f"Crawl stopped at the {max_pages}-page limit; additional same-origin links may remain."
            )
        if missing_headers:
            _add_finding(
                results["Findings"], "INFO", "Security headers not observed on every page",
                "Missing on at least one crawled response: " + ", ".join(sorted(missing_headers)) + ". Review the affected endpoints and intended policy.",
            )
        results["Summary"] = {
            "Pages Crawled": len(results["Pages"]),
            "HTML Pages Reviewed": pages_with_html,
            "Forms Observed": sum(page["Forms Found"] for page in results["Pages"]),
            "Findings Recorded": len(results["Findings"]),
            "Robots.txt Respected": True,
        }
        return results
    finally:
        session.close()


if __name__ == "__main__":
    target = input("Enter a website you own or are authorized to assess: ").strip()
    result = crawl_website(target)
    print(result)
