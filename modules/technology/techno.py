
import re
import requests

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag


# ============================================================
# TECHNOLOGY DETECTION MODULE 
# Enhanced Passive Detection
# ============================================================

MODULE_NAME = "Technology Detection"

USER_AGENT = "WebApp-Security-Toolkit/1.0"

REQUEST_TIMEOUT = 8
MAX_HTML_BYTES = 500_000
MAX_ASSET_BYTES = 200_000
MAX_ASSETS_TO_CHECK = 8

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}


# ============================================================
# HTML PARSER
# Collects metadata, script URLs, stylesheets and HTML clues
# ============================================================

class TechnologyHTMLParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.meta = []
        self.scripts = []
        self.stylesheets = []
        self.preloads = []
        self.attributes = []
        self.title_parts = []
        self.inside_title = False

    def handle_starttag(self, tag, attrs):
        self._process_tag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._process_tag(tag, attrs)

    def handle_data(self, data):
        if self.inside_title:
            self.title_parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.inside_title = False

    def _process_tag(self, tag, attrs):
        tag = tag.lower()
        attributes = {
            str(key).lower(): str(value or "")
            for key, value in attrs
            if key
        }

        self.attributes.append((tag, attributes))

        if tag == "title":
            self.inside_title = True

        if tag == "meta":
            self.meta.append(attributes)

        if tag == "script":
            src = attributes.get("src", "").strip()
            if src:
                self.scripts.append(src)

        if tag == "link":
            href = attributes.get("href", "").strip()
            rel = attributes.get("rel", "").lower()

            if href and "stylesheet" in rel:
                self.stylesheets.append(href)

            if href and (
                "preload" in rel or "modulepreload" in rel
            ):
                self.preloads.append(href)


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url):
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid target URL.")

    url = url.strip()

    if any(char.isspace() for char in url):
        raise ValueError("The URL must not contain spaces.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL does not contain a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")

    try:
        parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")

    return url


# ============================================================
# HTTP RESPONSE HELPERS
# ============================================================

def read_limited_response(response, max_bytes):
    """
    Read a bounded amount of response data.
    HTTPS certificate verification remains enabled.
    """

    content = bytearray()

    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue

        remaining = max_bytes - len(content)

        if remaining <= 0:
            break

        content.extend(chunk[:remaining])

        if len(content) >= max_bytes:
            break

    encoding = response.encoding or "utf-8"

    return bytes(content).decode(encoding, errors="replace")


def add_finding(results, category, technology, evidence,
                confidence="Medium"):
    """
    Add or merge evidence for a technology.
    Confidence describes indicator strength, not certainty
    that the technology is present on the origin server.
    """

    for item in results:
        if (
            item["category"] == category
            and item["technology"].lower() == technology.lower()
        ):
            if evidence not in item["evidence"]:
                item["evidence"].append(evidence)

            if confidence == "High":
                item["confidence"] = "High"

            return

    results.append({
        "category": category,
        "technology": technology,
        "evidence": [evidence],
        "confidence": confidence,
        "status": "Detected" if confidence == "High" else "Possible",
    })


def get_cookie_names(response):
    try:
        return {
            cookie.name.lower()
            for cookie in response.cookies
        }
    except Exception:
        return set()


def get_meta_values(parser, key):
    values = []

    for item in parser.meta:
        name = (
            item.get("name", "")
            or item.get("property", "")
            or item.get("http-equiv", "")
        ).lower()

        if name == key.lower():
            value = item.get("content", "").strip()

            if value:
                values.append(value)

    return values


def same_origin(url_a, url_b):
    """
    True only when scheme, hostname and effective port match.
    """

    a = urlparse(url_a)
    b = urlparse(url_b)

    def effective_port(parsed):
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and effective_port(a) == effective_port(b)
    )


def normalize_asset_url(base_url, asset_url):
    asset_url = asset_url.strip()

    if not asset_url:
        return None

    if asset_url.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    absolute = urldefrag(urljoin(base_url, asset_url))[0]
    parsed = urlparse(absolute)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None

    if not same_origin(base_url, absolute):
        return None

    return absolute


# ============================================================
# HTML PARSING
# ============================================================

def parse_html(html):
    parser = TechnologyHTMLParser()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass

    return parser


# ============================================================
# WEB SERVER DETECTION
# ============================================================

def detect_web_server(headers, results):
    server = headers.get("Server", "").strip()

    if not server:
        return

    server_lower = server.lower()

    known_servers = [
        ("nginx", r"\bnginx\b"),
        ("Apache HTTP Server", r"\bapache\b"),
        ("Microsoft IIS", r"\bmicrosoft-iis\b"),
        ("LiteSpeed", r"\blitespeed\b"),
        ("Caddy", r"\bcaddy\b"),
        ("OpenResty", r"\bopenresty\b"),
        ("Cloudflare edge", r"\bcloudflare\b"),
    ]

    matched = False

    for technology, pattern in known_servers:
        if re.search(pattern, server_lower):
            add_finding(
                results,
                "Web Server / Edge",
                technology,
                f"Matched Server response header: {server}",
                "High",
            )
            matched = True

    if not matched:
        add_finding(
            results,
            "Web Server / Edge",
            server,
            "Server response header exposed this value.",
            "High",
        )


# ============================================================
# BACKEND DETECTION
# ============================================================

def detect_backend(headers, cookie_names, html, results):
    powered_by = headers.get("X-Powered-By", "").strip()

    if powered_by:
        add_finding(
            results,
            "Backend",
            powered_by,
            "X-Powered-By response header.",
            "High",
        )

    x_generator = headers.get("X-Generator", "").strip()

    if x_generator:
        add_finding(
            results,
            "Backend / Generator",
            x_generator,
            "X-Generator response header.",
            "High",
        )

    html_lower = html.lower()

    # PHP
    if re.search(r"\bphp/\d+(?:\.\d+)*", powered_by, re.I):
        add_finding(
            results,
            "Backend",
            "PHP",
            "PHP version exposed in X-Powered-By.",
            "High",
        )
    elif "phpsessid" in cookie_names:
        add_finding(
            results,
            "Backend",
            "Possible PHP",
            "PHPSESSID session cookie observed.",
            "Medium",
        )

    # ASP.NET
    if (
        re.search(r"\basp\.net\b", powered_by, re.I)
        or "asp.net_sessionid" in cookie_names
        or "__viewstate" in html_lower
    ):
        add_finding(
            results,
            "Backend",
            "ASP.NET",
            "ASP.NET-related header, cookie or HTML indicator.",
            "Medium",
        )

    # Java
    if "jsessionid" in cookie_names:
        add_finding(
            results,
            "Backend",
            "Possible Java application",
            "JSESSIONID cookie observed.",
            "Medium",
        )

    # Node / Express
    if re.search(r"\bexpress\b", powered_by, re.I):
        add_finding(
            results,
            "Backend",
            "Node.js / Express",
            "Express identified in X-Powered-By.",
            "High",
        )

    # Django
    if "csrftoken" in cookie_names:
        add_finding(
            results,
            "Backend",
            "Possible Django",
            "csrftoken cookie observed; other applications may use this name.",
            "Low",
        )

    # Laravel
    if "laravel_session" in cookie_names:
        add_finding(
            results,
            "Backend",
            "Possible Laravel",
            "laravel_session cookie observed.",
            "Medium",
        )

    # Spring / Java hints
    if (
        "x-application-context" in {h.lower() for h in headers}
        or "spring" in powered_by.lower()
    ):
        add_finding(
            results,
            "Backend",
            "Possible Spring",
            "Spring-related response indicator observed.",
            "Medium",
        )


# ============================================================
# CMS DETECTION
# ============================================================

def detect_cms(html, headers, parser, results):
    text = html.lower()

    generator_values = " ".join(
        get_meta_values(parser, "generator")
    ).lower()

    if (
        "wp-content/" in text
        or "wp-includes/" in text
        or "wordpress" in generator_values
    ):
        add_finding(
            results,
            "CMS",
            "WordPress",
            "WordPress generator metadata or asset path observed.",
            "High",
        )

    if (
        "drupal.settings" in text
        or "drupal.js" in text
        or "drupal" in generator_values
        or "x-drupal-cache" in {h.lower() for h in headers}
    ):
        add_finding(
            results,
            "CMS",
            "Drupal",
            "Drupal-related HTML, generator or response header observed.",
            "Medium",
        )

    if (
        "com_content" in text
        or "/media/system/js/" in text
        or "joomla" in generator_values
    ):
        add_finding(
            results,
            "CMS",
            "Joomla",
            "Joomla-related HTML path or generator metadata observed.",
            "Medium",
        )

    if "shopify" in text or "cdn.shopify.com" in text:
        add_finding(
            results,
            "CMS / E-commerce",
            "Possible Shopify",
            "Shopify-related page or asset indicator observed.",
            "Medium",
        )

    if (
        "magento" in text
        or "mage-cache-storage" in text
        or "mage/cookies" in text
    ):
        add_finding(
            results,
            "CMS / E-commerce",
            "Possible Magento",
            "Magento-related HTML indicator observed.",
            "Medium",
        )


# ============================================================
# FRONTEND FRAMEWORK DETECTION
# ============================================================

def detect_frontend(html, parser, results):
    text = html.lower()

    # React / Next.js
    if (
        "__next_data__" in text
        or 'id="__next"' in text
        or "id='__next'" in text
    ):
        add_finding(
            results,
            "Frontend Framework",
            "Next.js",
            "Next.js page root or serialized data marker observed.",
            "High",
        )

    elif (
        'id="root"' in text
        or "id='root'" in text
        or "data-reactroot" in text
        or "react-dom" in text
    ):
        add_finding(
            results,
            "Frontend Framework",
            "Possible React",
            "React-related root, DOM attribute or script indicator observed.",
            "Medium",
        )

    # Vue
    if (
        "data-v-" in text
        or "vue.runtime" in text
        or "vue.global" in text
        or "data-server-rendered" in text
    ):
        add_finding(
            results,
            "Frontend Framework",
            "Vue.js",
            "Vue-related DOM attributes or script indicator observed.",
            "Medium",
        )

    # Angular
    if (
        "ng-version=" in text
        or "_ngcontent-" in text
        or "ng-app" in text
    ):
        add_finding(
            results,
            "Frontend Framework",
            "Angular",
            "Angular-related HTML attributes observed.",
            "High" if "ng-version=" in text else "Medium",
        )

    # jQuery
    if re.search(r"jquery(?:\.min)?(?:-\d+(?:\.\d+)*)?\.js", text):
        add_finding(
            results,
            "JavaScript Library",
            "jQuery",
            "jQuery script filename referenced in HTML.",
            "High",
        )

    # Svelte
    if "svelte-" in text or "sveltekit" in text:
        add_finding(
            results,
            "Frontend Framework",
            "Possible Svelte / SvelteKit",
            "Svelte-related HTML marker observed.",
            "Medium",
        )

    # Nuxt
    if "__nuxt" in text or "nuxt" in text and "data-nuxt" in text:
        add_finding(
            results,
            "Frontend Framework",
            "Possible Nuxt",
            "Nuxt-related HTML marker observed.",
            "Medium",
        )

    # Webpack
    if "webpack" in text or "webpackbootstrap" in text:
        add_finding(
            results,
            "Build Tool",
            "Possible Webpack",
            "Webpack-related runtime marker observed.",
            "Low",
        )

    # Meta generator
    generators = get_meta_values(parser, "generator")

    for generator in generators:
        add_finding(
            results,
            "Generator",
            generator,
            "HTML generator metadata.",
            "High",
        )


# ============================================================
# CDN / PROXY / HOSTING INDICATORS
# ============================================================

def detect_infrastructure(headers, results):
    lower_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    # Cloudflare
    if any(
        name in lower_headers
        for name in ("cf-ray", "cf-cache-status", "cf-mitigated")
    ):
        add_finding(
            results,
            "CDN / Proxy",
            "Cloudflare",
            "Cloudflare-related response header observed.",
            "High",
        )

    # Amazon CloudFront
    if any(
        name in lower_headers
        for name in ("x-amz-cf-id", "x-amz-cf-pop")
    ):
        add_finding(
            results,
            "CDN / Proxy",
            "Amazon CloudFront",
            "CloudFront-related response header observed.",
            "High",
        )

    # Akamai
    if "x-akamai-transformed" in lower_headers:
        add_finding(
            results,
            "CDN / Proxy",
            "Akamai",
            "Akamai-related response header observed.",
            "High",
        )

    # Fastly
    if (
        "x-served-by" in lower_headers
        and "fastly" in lower_headers.get("via", "").lower()
    ):
        add_finding(
            results,
            "CDN / Proxy",
            "Possible Fastly",
            "Fastly-related Via / served-by response indicators.",
            "Medium",
        )

    # Vercel
    if (
        "x-vercel-id" in lower_headers
        or "server" in lower_headers
        and lower_headers["server"].lower() == "vercel"
    ):
        add_finding(
            results,
            "Hosting / Platform",
            "Vercel",
            "Vercel-related response header observed.",
            "High",
        )

    # Netlify
    if "netlify" in lower_headers.get("server", "").lower():
        add_finding(
            results,
            "Hosting / Platform",
            "Possible Netlify",
            "Netlify-related Server header observed.",
            "Medium",
        )

    # Sucuri
    if "x-sucuri-id" in lower_headers:
        add_finding(
            results,
            "CDN / Proxy",
            "Sucuri",
            "Sucuri-related response header observed.",
            "High",
        )


# ============================================================
# PUBLIC WAF / EDGE-PROTECTION INDICATORS
# These indicators are heuristic and cannot prove that a WAF is
# enabled, inspecting every request, or correctly configured.
# ============================================================

def detect_waf_indicators(headers, cookie_names, status_code, results):
    lower_headers = {
        str(key).lower(): str(value)
        for key, value in headers.items()
    }
    lower_cookies = {
        str(name).lower()
        for name in cookie_names
    }
    server = lower_headers.get("server", "").lower()

    # Cloudflare's challenge marker is a direct signal that an edge
    # challenge was returned. Other Cloudflare headers identify the
    # edge service but do not by themselves prove WAF enforcement.
    cf_mitigated = lower_headers.get("cf-mitigated", "").strip().lower()
    if cf_mitigated:
        add_finding(
            results,
            "WAF / Edge Protection",
            "Cloudflare challenge indicator",
            (
                f"cf-mitigated response header: {cf_mitigated}; "
                f"HTTP status: {status_code}. This indicates a challenge "
                "response, not the overall WAF configuration."
            ),
            "High",
        )
    elif (
        "cf-ray" in lower_headers
        or "cf-cache-status" in lower_headers
        or "cloudflare" in server
    ):
        add_finding(
            results,
            "WAF / Edge Protection",
            "Possible Cloudflare edge protection",
            "Cloudflare-related response indicators were observed. "
            "They do not confirm that Cloudflare WAF rules are enabled.",
            "Medium",
        )

    # Sucuri exposes service-specific response headers on some sites.
    sucuri_markers = [
        name for name in ("x-sucuri-id", "x-sucuri-cache")
        if name in lower_headers
    ]
    if sucuri_markers or "sucuri" in server:
        evidence = (
            "Observed Sucuri-related response indicators: "
            + ", ".join(sucuri_markers or ["Server header"])
            + ". This suggests an edge service, but does not confirm "
            "active or complete WAF coverage."
        )
        add_finding(
            results,
            "WAF / Edge Protection",
            "Possible Sucuri edge protection",
            evidence,
            "Medium",
        )

    # Imperva/Incapsula response headers and cookies are useful public
    # fingerprints, though they may be absent or intentionally hidden.
    imperva_headers = [
        name for name in ("x-iinfo", "x-cdn")
        if name in lower_headers
        and "incapsula" in lower_headers.get(name, "").lower()
    ]
    imperva_cookies = sorted(
        name for name in lower_cookies
        if name.startswith(("incap_ses_", "visid_incap_", "nlbi_"))
    )
    if imperva_headers or imperva_cookies:
        indicators = imperva_headers + imperva_cookies
        add_finding(
            results,
            "WAF / Edge Protection",
            "Possible Imperva / Incapsula protection",
            "Observed Imperva-related indicators: "
            + ", ".join(indicators)
            + ". This is a service fingerprint, not proof of WAF coverage.",
            "Medium",
        )

    # Bot-management cookies indicate edge-side traffic controls, not
    # necessarily a general-purpose web application firewall.
    akamai_cookies = sorted(
        name for name in lower_cookies
        if name in {"_abck", "bm_sz", "bm_sv", "ak_bmsc"}
    )
    if akamai_cookies:
        add_finding(
            results,
            "WAF / Edge Protection",
            "Possible Akamai bot protection",
            "Akamai Bot Manager-related cookie(s) observed: "
            + ", ".join(akamai_cookies)
            + ". This does not confirm general WAF coverage.",
            "Medium",
        )

    # AWS WAF can include this marker in challenge/CAPTCHA responses.
    aws_action = lower_headers.get("x-amzn-waf-action", "").strip()
    if aws_action:
        add_finding(
            results,
            "WAF / Edge Protection",
            "AWS WAF action indicator",
            f"x-amzn-waf-action response header: {aws_action}; "
            f"HTTP status: {status_code}.",
            "High",
        )

    # Product banner is a weak fingerprint; do not infer protection from
    # a generic 403 response alone.
    if "fortiweb" in server:
        add_finding(
            results,
            "WAF / Edge Protection",
            "Possible FortiWeb edge protection",
            "FortiWeb was named in the Server response header. "
            "The banner alone does not verify active WAF rules.",
            "Medium",
        )


# ============================================================
# ASSET ANALYSIS
# Fetch only a small number of same-origin public JS/CSS assets
# ============================================================

def detect_from_assets(session, base_url, parser, results, warnings):
    asset_urls = []

    for asset in parser.scripts + parser.stylesheets + parser.preloads:
        normalized = normalize_asset_url(base_url, asset)

        if normalized and normalized not in asset_urls:
            asset_urls.append(normalized)

        if len(asset_urls) >= MAX_ASSETS_TO_CHECK:
            break

    inspected = 0

    for asset_url in asset_urls:
        try:
            with session.get(
                asset_url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=True,
                stream=True,
            ) as response:

                if not same_origin(base_url, response.url):
                    continue

                content_type = response.headers.get(
                    "Content-Type", ""
                ).lower()

                path = urlparse(response.url).path.lower()

                if (
                    "javascript" not in content_type
                    and "text/css" not in content_type
                    and not path.endswith((".js", ".mjs", ".css"))
                ):
                    continue

                if response.status_code >= 400:
                    continue

                asset_text = read_limited_response(
                    response,
                    MAX_ASSET_BYTES,
                ).lower()

                inspected += 1

                # Framework clues from asset URL or content
                combined = path + " " + asset_text[:MAX_ASSET_BYTES]

                if "react-dom" in combined or "react.production" in combined:
                    add_finding(
                        results,
                        "Frontend Framework",
                        "React",
                        f"React-related marker in same-origin asset: {path}",
                        "High",
                    )

                if "vue.runtime" in combined or "vue.global" in combined:
                    add_finding(
                        results,
                        "Frontend Framework",
                        "Vue.js",
                        f"Vue-related marker in same-origin asset: {path}",
                        "High",
                    )

                if "angular" in path and (
                    "runtime" in path or "main" in path
                ):
                    add_finding(
                        results,
                        "Frontend Framework",
                        "Possible Angular",
                        f"Angular-like bundle filename: {path}",
                        "Medium",
                    )

                if "jquery" in path:
                    add_finding(
                        results,
                        "JavaScript Library",
                        "jQuery",
                        f"jQuery-related asset filename: {path}",
                        "High",
                    )

                if "wp-content/" in path:
                    add_finding(
                        results,
                        "CMS",
                        "WordPress",
                        f"WordPress asset path: {path}",
                        "High",
                    )

                if "drupal" in path:
                    add_finding(
                        results,
                        "CMS",
                        "Possible Drupal",
                        f"Drupal-related asset path: {path}",
                        "Medium",
                    )

                if "webpack" in combined:
                    add_finding(
                        results,
                        "Build Tool",
                        "Possible Webpack",
                        f"Webpack-related marker in asset: {path}",
                        "Low",
                    )

        except requests.exceptions.SSLError:
            warnings.append(
                "A linked asset could not be checked because TLS "
                "certificate verification failed."
            )

        except requests.exceptions.RequestException:
            warnings.append(
                "One or more linked assets could not be fetched."
            )

        except Exception:
            warnings.append(
                "An unexpected error occurred while inspecting an asset."
            )

    return {
        "assets_discovered": len(asset_urls),
        "assets_inspected": inspected,
    }


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def detect_technologies(url):
    results = []
    warnings = []

    try:
        target_url = validate_url(url)

        with requests.Session() as session:
            session.headers.update(HEADERS)

            # One normal GET request; no brute force or exploit attempts.
            with session.get(
                target_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=True,
                stream=True,
            ) as response:

                final_url = response.url
                status_code = response.status_code
                headers = response.headers.copy()
                html = read_limited_response(
                    response,
                    MAX_HTML_BYTES,
                )

                cookie_names = get_cookie_names(response)
                history_count = len(response.history)

            parser = parse_html(html)

            # Main page analysis
            detect_web_server(headers, results)

            detect_backend(
                headers,
                cookie_names,
                html,
                results,
            )

            detect_cms(
                html,
                headers,
                parser,
                results,
            )

            detect_frontend(
                html,
                parser,
                results,
            )

            detect_infrastructure(
                headers,
                results,
            )

            detect_waf_indicators(
                headers,
                cookie_names,
                status_code,
                results,
            )

            # Limited same-origin linked asset analysis
            asset_summary = detect_from_assets(
                session,
                final_url,
                parser,
                results,
                warnings,
            )

        if history_count:
            warnings.append(
                f"The target redirected {history_count} time(s) "
                "before reaching the final URL."
            )

        if status_code >= 400:
            warnings.append(
                f"The server returned HTTP {status_code}; "
                "detection results may be incomplete."
            )

        if len(html.encode("utf-8", errors="ignore")) >= MAX_HTML_BYTES:
            warnings.append(
                "The HTML response was truncated at the configured size limit."
            )

        if not results:
            warnings.append(
                "No recognizable technology indicators were found. "
                "This does not mean the website uses no technologies."
            )

        return {
            "module": MODULE_NAME,
            "target": target_url,
            "final_url": final_url,
            "status_code": status_code,
            "technologies": results,
            "warnings": warnings,
            "asset_summary": asset_summary,
            "error": None,
        }

    except requests.exceptions.SSLError:
        return {
            "module": MODULE_NAME,
            "target": str(url),
            "final_url": None,
            "status_code": None,
            "technologies": [],
            "warnings": warnings,
            "asset_summary": {
                "assets_discovered": 0,
                "assets_inspected": 0,
            },
            "error": (
                "TLS certificate verification failed. "
                "Check the target URL and certificate."
            ),
        }

    except requests.exceptions.Timeout:
        return {
            "module": MODULE_NAME,
            "target": str(url),
            "final_url": None,
            "status_code": None,
            "technologies": [],
            "warnings": warnings,
            "asset_summary": {
                "assets_discovered": 0,
                "assets_inspected": 0,
            },
            "error": "The target did not respond before the timeout.",
        }

    except requests.exceptions.RequestException as error:
        return {
            "module": MODULE_NAME,
            "target": str(url),
            "final_url": None,
            "status_code": None,
            "technologies": [],
            "warnings": warnings,
            "asset_summary": {
                "assets_discovered": 0,
                "assets_inspected": 0,
            },
            "error": f"Request failed: {error}",
        }

    except ValueError as error:
        return {
            "module": MODULE_NAME,
            "target": str(url),
            "final_url": None,
            "status_code": None,
            "technologies": [],
            "warnings": warnings,
            "asset_summary": {
                "assets_discovered": 0,
                "assets_inspected": 0,
            },
            "error": str(error),
        }


def check_waf_indicators(url):
    """Return a focused WAF/edge-indicator report for the GUI card."""
    scan_result = detect_technologies(url)
    indicators = [
        item for item in scan_result.get("technologies", [])
        if item.get("category") == "WAF / Edge Protection"
    ]

    if scan_result.get("error"):
        assessment = (
            "Could not assess public WAF indicators because the HTTP scan "
            "did not complete."
        )
    elif indicators:
        assessment = (
            "Possible WAF or edge-protection indicators were found. "
            "They do not confirm that protection is enabled or correctly configured."
        )
    else:
        assessment = (
            "No public WAF indicators were identified. This does not prove "
            "that a firewall or WAF is absent."
        )

    return {
        "module": "WAF / Firewall Indicators",
        "target": scan_result.get("target", str(url)),
        "final_url": scan_result.get("final_url"),
        "status_code": scan_result.get("status_code"),
        "assessment": assessment,
        "indicators": indicators,
        "warnings": scan_result.get("warnings", []),
        "error": scan_result.get("error"),
    }


# ============================================================
# REPORT FORMATTER
# ============================================================

def format_technology_report(scan_result):
    lines = [
        "=" * 65,
        "           WEB APPLICATION TECHNOLOGY DETECTION",
        "=" * 65,
        f"Target URL: {scan_result.get('target')}",
        f"Final URL: {scan_result.get('final_url') or 'Unavailable'}",
        f"HTTP Status: {scan_result.get('status_code') or 'Unavailable'}",
        "",
    ]

    error = scan_result.get("error")

    if error:
        lines.extend([
            "SCAN ERROR",
            "-" * 65,
            error,
        ])

    else:
        technologies = scan_result.get("technologies", [])

        lines.extend([
            f"Technologies / Indicators Found: {len(technologies)}",
            "-" * 65,
        ])

        if technologies:
            for item in technologies:
                lines.extend([
                    f"[{item['category']}] {item['technology']}",
                    f"Status: {item.get('status', 'Possible')}",
                    f"Confidence: {item['confidence']}",
                    "Evidence:",
                ])

                for evidence in item["evidence"]:
                    lines.append(f"  - {evidence}")

                lines.append("")

        else:
            lines.append("No recognizable indicators were detected.")
            lines.append("")

        assets = scan_result.get("asset_summary", {})

        lines.extend([
            "ASSET ANALYSIS",
            "-" * 65,
            f"Same-origin assets discovered: "
            f"{assets.get('assets_discovered', 0)}",
            f"Same-origin assets inspected: "
            f"{assets.get('assets_inspected', 0)}",
            "",
        ])

    warnings = scan_result.get("warnings", [])

    if warnings:
        lines.extend([
            "WARNINGS / LIMITATIONS",
            "-" * 65,
        ])

        for warning in warnings:
            lines.append(f"- {warning}")

        lines.append("")

    lines.extend([
        "INTERPRETATION",
        "-" * 65,
        "Detected means a strong public indicator was observed.",
        "Possible means the evidence is suggestive, not conclusive.",
        "Not identified means no reliable indicator was found;",
        "it does not prove the technology is absent.",
        "",
        "This scan examines a limited public HTTP response and a",
        "small number of same-origin linked assets. It does not",
        "execute JavaScript, scan ports, bypass authentication,",
        "or verify hidden origin infrastructure. WAF results are",
        "public indicators only; no indicator does not prove that",
        "a firewall or WAF is absent.",
        "=" * 65,
    ])

    return "\n".join(lines)


# ============================================================
# ALIAS FOR COMPATIBILITY
# ============================================================

def scan_technologies(url):
    return detect_technologies(url)


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":
    target = input(
        "Enter an authorized website URL to inspect: "
    ).strip()

    result = detect_technologies(target)

    print()
    print(format_technology_report(result))
