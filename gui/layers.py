import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog

import requests
import threading
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
try:
    from gui.visuals import create_icon_badge, create_illustration
except ModuleNotFoundError:
    from visuals import create_icon_badge, create_illustration


# ============================================================
# SETTINGS
# ============================================================

APP_TITLE = "Web Application Security Toolkit - Layer Scanner"

BG_COLOR = "#071327"
CARD_COLOR = "#101E34"
CARD_BORDER = "#29415F"
TEXT_COLOR = "#f8fafc"
SECONDARY_TEXT = "#A8BCD4"

ACCENT = "#3B82F6"
ACCENT_HOVER = "#2563EB"

GREEN = "#20D6B5"
ORANGE = "#F5B942"
RED = "#FB7185"

DARK_BUTTON = "#243650"
DARK_BUTTON_HOVER = "#334B6C"

REQUEST_TIMEOUT = 8

USER_AGENT = "WebApp-Security-Toolkit/1.0"


# ============================================================
# SECURITY LAYERS
# ============================================================

SECURITY_LAYERS = {

    "Network & Transport Layer": [
        "HTTPS availability",
        "TLS certificate information",
        "Secure connection verification",
    ],

    "Web Server & HTTP Layer": [
        "HTTP security headers",
        "Server information disclosure",
        "HTTP methods",
        "Directory listing indicators",
    ],

    "Application & API Layer": [
        "Public endpoint discovery",
        "API-related endpoint indicators",
        "Authentication review",
        "Access-control review",
    ],

    "Data & Database Layer": [
        "Sensitive path exposure indicators",
        "Database error disclosure indicators",
        "Publicly accessible file indicators",
    ],
}


# ============================================================
# RESULT HELPER
# ============================================================

def result(status, title, details):
    return {
        "status": status,
        "title": title,
        "details": details
    }


# ============================================================
# URL
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError(
            "Please enter a valid website URL."
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing usernames or passwords are not allowed."
        )

    if any(char.isspace() for char in url):
        raise ValueError(
            "The URL cannot contain spaces."
        )

    return url.rstrip("/")


# ============================================================
# REQUEST SESSION
# ============================================================

def make_session():

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*"
    })

    session.verify = True

    return session


def safe_request(session, url, method="GET"):

    return session.request(
        method=method,
        url=url,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )


# ============================================================
# NETWORK & TRANSPORT
# ============================================================

def check_network_transport(target, session):

    findings = []

    parsed = urlparse(target)

    hostname = parsed.hostname

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if parsed.scheme == "https":

        try:

            response = safe_request(
                session,
                target
            )

            findings.append(
                result(
                    "PASS",
                    "HTTPS Connection",
                    f"HTTPS responded with HTTP "
                    f"status {response.status_code}."
                )
            )

        except requests.exceptions.SSLError:

            findings.append(
                result(
                    "WARNING",
                    "HTTPS Certificate Validation",
                    "TLS certificate validation failed. "
                    "Review the certificate and hostname."
                )
            )

        except requests.exceptions.RequestException as exc:

            findings.append(
                result(
                    "WARNING",
                    "HTTPS Connection",
                    f"HTTPS could not be verified: {exc}"
                )
            )

    else:

        findings.append(
            result(
                "WARNING",
                "HTTPS Availability",
                "The supplied URL uses HTTP instead of HTTPS."
            )
        )

    # --------------------------------------------------------
    # TLS CERTIFICATE
    # --------------------------------------------------------

    if parsed.scheme == "https":

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (
                    hostname,
                    parsed.port or 443
                ),
                timeout=REQUEST_TIMEOUT
            ) as raw_socket:

                with context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname
                ) as tls_socket:

                    certificate = tls_socket.getpeercert()

                    tls_version = tls_socket.version()

            expiry_text = certificate.get("notAfter")

            if expiry_text:

                expiry_date = datetime.strptime(
                    expiry_text,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(
                    tzinfo=timezone.utc
                )

                remaining = (
                    expiry_date -
                    datetime.now(timezone.utc)
                ).days

                if remaining < 0:

                    findings.append(
                        result(
                            "WARNING",
                            "TLS Certificate Expiry",
                            f"The certificate appears expired. "
                            f"Expiry: {expiry_text}"
                        )
                    )

                elif remaining <= 30:

                    findings.append(
                        result(
                            "WARNING",
                            "TLS Certificate Expiry",
                            f"The certificate expires in "
                            f"{remaining} days."
                        )
                    )

                else:

                    findings.append(
                        result(
                            "PASS",
                            "TLS Certificate Expiry",
                            f"Certificate expiry: {expiry_text}. "
                            f"Approximately {remaining} days remain."
                        )
                    )

            findings.append(
                result(
                    "INFO",
                    "Negotiated TLS Version",
                    f"The connection negotiated "
                    f"{tls_version or 'unknown TLS version'}."
                )
            )

        except (
            OSError,
            ssl.SSLError,
            ValueError
        ) as exc:

            findings.append(
                result(
                    "WARNING",
                    "TLS Certificate Check",
                    f"Could not complete TLS certificate "
                    f"check: {exc}"
                )
            )

    return findings


# ============================================================
# WEB SERVER & HTTP
# ============================================================

def check_web_server_http(target, session):

    findings = []

    try:

        response = safe_request(
            session,
            target
        )

    except requests.exceptions.RequestException as exc:

        return [
            result(
                "WARNING",
                "HTTP Assessment",
                f"Could not retrieve target page: {exc}"
            )
        ]

    headers = response.headers

    # --------------------------------------------------------
    # SECURITY HEADERS
    # --------------------------------------------------------

    security_headers = {

        "Strict-Transport-Security":
            "Helps enforce HTTPS.",

        "Content-Security-Policy":
            "Helps restrict content sources.",

        "X-Content-Type-Options":
            "Helps prevent MIME sniffing.",

        "X-Frame-Options":
            "Can help reduce clickjacking risk.",

        "Referrer-Policy":
            "Controls referrer information."
    }

    for header, explanation in security_headers.items():

        if header in headers:

            findings.append(
                result(
                    "PASS",
                    f"Security Header: {header}",
                    f"Present. {explanation}"
                )
            )

        else:

            findings.append(
                result(
                    "INFO",
                    f"Security Header: {header}",
                    f"Not observed. {explanation}"
                )
            )

    # --------------------------------------------------------
    # SERVER DISCLOSURE
    # --------------------------------------------------------

    server_header = headers.get("Server")

    powered_by = headers.get(
        "X-Powered-By"
    )

    if server_header or powered_by:

        details = []

        if server_header:
            details.append(
                f"Server: {server_header}"
            )

        if powered_by:
            details.append(
                f"X-Powered-By: {powered_by}"
            )

        findings.append(
            result(
                "WARNING",
                "Server Information Disclosure",
                "; ".join(details)
            )
        )

    else:

        findings.append(
            result(
                "PASS",
                "Server Information Disclosure",
                "Server and X-Powered-By headers "
                "were not observed."
            )
        )

    # --------------------------------------------------------
    # HTTP METHODS
    # --------------------------------------------------------

    try:

        options_response = safe_request(
            session,
            target,
            method="OPTIONS"
        )

        allow_header = options_response.headers.get(
            "Allow"
        )

        if allow_header:

            findings.append(
                result(
                    "INFO",
                    "HTTP Methods",
                    f"Server advertised methods: "
                    f"{allow_header}"
                )
            )

        else:

            findings.append(
                result(
                    "INFO",
                    "HTTP Methods",
                    f"OPTIONS returned HTTP "
                    f"{options_response.status_code}. "
                    f"No Allow header was observed."
                )
            )

    except requests.exceptions.RequestException as exc:

        findings.append(
            result(
                "INFO",
                "HTTP Methods",
                f"Could not inspect OPTIONS: {exc}"
            )
        )

    # --------------------------------------------------------
    # DIRECTORY LISTING
    # --------------------------------------------------------

    body = response.text[
        :200000
    ].lower()

    listing_markers = [
        "index of /",
        "directory listing for",
        "parent directory"
    ]

    if any(
        marker in body
        for marker in listing_markers
    ):

        findings.append(
            result(
                "WARNING",
                "Possible Directory Listing",
                "A common directory-listing indicator "
                "was detected. Verify manually."
            )
        )

    else:

        findings.append(
            result(
                "INFO",
                "Directory Listing",
                "No common directory-listing indicator "
                "was found on the homepage."
            )
        )

    return findings


# ============================================================
# APPLICATION & API
# ============================================================

def check_application_api(target, session):

    findings = []

    parsed = urlparse(target)

    base = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
    )

    # --------------------------------------------------------
    # ROBOTS
    # --------------------------------------------------------

    for path in [
        "/robots.txt",
        "/sitemap.xml"
    ]:

        url = urljoin(
            base + "/",
            path.lstrip("/")
        )

        try:

            response = safe_request(
                session,
                url
            )

            if response.status_code == 200:

                findings.append(
                    result(
                        "INFO",
                        f"Public Discovery File: {path}",
                        "The path returned HTTP 200. "
                        "Review contents for unintended disclosure."
                    )
                )

            else:

                findings.append(
                    result(
                        "INFO",
                        f"Public Discovery File: {path}",
                        f"Returned HTTP "
                        f"{response.status_code}."
                    )
                )

        except requests.exceptions.RequestException as exc:

            findings.append(
                result(
                    "INFO",
                    f"Public Discovery File: {path}",
                    f"Could not inspect path: {exc}"
                )
            )

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    findings.append(
        result(
            "MANUAL",
            "Authentication Review",
            "Not fully tested. Review login, password "
            "recovery, session handling, MFA and "
            "account lockout using authorized test accounts."
        )
    )

    # --------------------------------------------------------
    # ACCESS CONTROL
    # --------------------------------------------------------

    findings.append(
        result(
            "MANUAL",
            "Access-Control Review",
            "Not fully tested. Review role permissions "
            "and object-level access using authorized "
            "test accounts."
        )
    )

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

    findings.append(
        result(
            "MANUAL",
            "Input Validation",
            "Not tested with attack payloads. Review "
            "server-side validation and output encoding "
            "in an authorized test environment."
        )
    )

    return findings


# ============================================================
# DATA & DATABASE
# ============================================================

def check_data_database(target, session):

    findings = []

    parsed = urlparse(target)

    base = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
    )

    sensitive_paths = [
        ".env",
        ".git/HEAD",
        "backup.sql",
        "database.sql"
    ]

    # --------------------------------------------------------
    # SENSITIVE PATHS
    # --------------------------------------------------------

    for path in sensitive_paths:

        url = urljoin(
            base + "/",
            path
        )

        try:

            response = safe_request(
                session,
                url
            )

            if response.status_code == 200:

                findings.append(
                    result(
                        "WARNING",
                        f"Sensitive Path Needs Review: /{path}",
                        "The path returned HTTP 200. "
                        "This is not by itself proof of exposure. "
                        "Verify the response manually."
                    )
                )

            else:

                findings.append(
                    result(
                        "INFO",
                        f"Sensitive Path: /{path}",
                        f"Returned HTTP "
                        f"{response.status_code}."
                    )
                )

        except requests.exceptions.RequestException as exc:

            findings.append(
                result(
                    "INFO",
                    f"Sensitive Path: /{path}",
                    f"Could not inspect path: {exc}"
                )
            )

    # --------------------------------------------------------
    # DATABASE ERRORS
    # --------------------------------------------------------

    try:

        response = safe_request(
            session,
            target
        )

        body = response.text[
            :200000
        ].lower()

        error_markers = [
            "sql syntax",
            "mysql_fetch",
            "mysqli_sql_exception",
            "postgresql error",
            "sqlite error",
            "ora-",
            "odbc sql"
        ]

        matches = [
            marker
            for marker in error_markers
            if marker in body
        ]

        if matches:

            findings.append(
                result(
                    "WARNING",
                    "Possible Database Error Disclosure",
                    "Common database error indicators "
                    "were detected. Verify manually."
                )
            )

        else:

            findings.append(
                result(
                    "INFO",
                    "Database Error Disclosure",
                    "No configured database error indicators "
                    "were detected on the homepage."
                )
            )

    except requests.exceptions.RequestException as exc:

        findings.append(
            result(
                "INFO",
                "Database Error Disclosure",
                f"Could not inspect homepage: {exc}"
            )
        )

    # --------------------------------------------------------
    # DATABASE ACCESS CONTROL
    # --------------------------------------------------------

    findings.append(
        result(
            "MANUAL",
            "Database Access Control",
            "Internal database permissions, credentials, "
            "encryption and network isolation cannot be "
            "verified through public HTTP checks alone."
        )
    )

    return findings


# ============================================================
# LAYER FUNCTIONS
# ============================================================

LAYER_FUNCTIONS = {

    "Network & Transport Layer":
        check_network_transport,

    "Web Server & HTTP Layer":
        check_web_server_http,

    "Application & API Layer":
        check_application_api,

    "Data & Database Layer":
        check_data_database
}


# ============================================================
# MAIN SCAN FUNCTION
# ============================================================

def scan_selected_layers(
    target,
    selected_layers
):

    target = normalize_url(
        target
    )

    if not selected_layers:

        raise ValueError(
            "Select at least one security layer."
        )

    results = {

        "target":
            target,

        "scan_time":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "selected_layers":
            list(selected_layers),

        "layers": {}
    }

    session = make_session()

    try:

        for layer_name in selected_layers:

            if layer_name not in LAYER_FUNCTIONS:

                continue

            try:

                function = LAYER_FUNCTIONS[
                    layer_name
                ]

                findings = function(
                    target,
                    session
                )

                results[
                    "layers"
                ][layer_name] = findings

            except Exception as exc:

                results[
                    "layers"
                ][layer_name] = [

                    result(
                        "ERROR",
                        "Layer Scan Error",
                        str(exc)
                    )
                ]

    finally:

        session.close()

    return results


# ============================================================
# REPORT FORMAT
# ============================================================

def format_results(results):

    lines = []

    lines.append(
        "=" * 70
    )

    lines.append(
        "WEB APPLICATION SECURITY TOOLKIT"
    )

    lines.append(
        "SECURITY LAYER SCAN REPORT"
    )

    lines.append(
        "=" * 70
    )

    lines.append(
        f"Target: {results['target']}"
    )

    lines.append(
        f"Scan Time: {results['scan_time']}"
    )

    lines.append("")

    lines.append(
        "Selected Layers:"
    )

    for layer in results[
        "selected_layers"
    ]:

        lines.append(
            f"  • {layer}"
        )

    for layer_name, findings in results[
        "layers"
    ].items():

        lines.append("")

        lines.append(
            "-" * 70
        )

        lines.append(
            layer_name
        )

        lines.append(
            "-" * 70
        )

        for item in findings:

            lines.append(
                f"[{item['status']}] "
                f"{item['title']}"
            )

            lines.append(
                f"    {item['details']}"
            )

            lines.append("")

    lines.append(
        "=" * 70
    )

    lines.append(
        "END OF REPORT"
    )

    lines.append(
        "=" * 70
    )

    return "\n".join(lines)


# ============================================================
# GUI
# ============================================================

class LayerScannerApp(ctk.CTkFrame):

    def __init__(self, master, on_back=None, on_scan_state=None):

        super().__init__(master, fg_color=BG_COLOR)

        self.on_back = on_back
        self.on_scan_state = on_scan_state

        self.scanning = False

        self.last_results = None

        self.layer_vars = {

            name:
                tk.BooleanVar(master=self, value=False)

            for name in SECURITY_LAYERS
        }

        self.build_interface()


    # ========================================================
    # MAIN INTERFACE
    # ========================================================

    def build_interface(self):

        # ----------------------------------------------------
        # FIX: WHOLE PAGE IS SCROLLABLE
        # ----------------------------------------------------

        self.main_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=BG_COLOR,
            corner_radius=0,
            scrollbar_button_color=DARK_BUTTON,
            scrollbar_button_hover_color=DARK_BUTTON_HOVER
        )

        self.main_scroll.pack(
            fill="both",
            expand=True,
            padx=0,
            pady=0
        )

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = ctk.CTkFrame(
            self.main_scroll,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=CARD_BORDER
        )

        header.pack(
            fill="x",
            padx=18,
            pady=(18, 10)
        )

        title_row = ctk.CTkFrame(
            header,
            fg_color="transparent"
        )
        title_row.pack(
            fill="x",
            padx=20,
            pady=(16, 4)
        )

        create_icon_badge(
            title_row,
            "layers",
            accent="#A78BFA",
            size=44,
            bg=CARD_COLOR
        ).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            title_row,
            text="Security Layer Scanner",
            font=("Arial", 25, "bold"),
            text_color=TEXT_COLOR
        ).pack(
            side="left",
            anchor="w"
        )

        if self.on_back:
            self.back_button = ctk.CTkButton(
                title_row,
                text="BACK TO MODULES",
                width=150,
                fg_color=DARK_BUTTON,
                hover_color=DARK_BUTTON_HOVER,
                command=self.go_back
            )
            self.back_button.pack(side="right")

        ctk.CTkLabel(
            header,
            text=(
                "Select one or more website security layers "
                "to assess."
            ),
            font=("Arial", 13),
            text_color=SECONDARY_TEXT
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 16)
        )

        create_illustration(
            self.main_scroll,
            "layers",
            width=320,
            height=92,
            bg=BG_COLOR
        ).pack(anchor="e", padx=22, pady=(0, 3))

        # ----------------------------------------------------
        # TARGET
        # ----------------------------------------------------

        target_card = ctk.CTkFrame(
            self.main_scroll,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=CARD_BORDER
        )

        target_card.pack(
            fill="x",
            padx=18,
            pady=8
        )

        ctk.CTkLabel(
            target_card,
            text="Target Website",
            font=("Arial", 16, "bold"),
            text_color=TEXT_COLOR
        ).pack(
            anchor="w",
            padx=16,
            pady=(12, 5)
        )

        self.url_entry = ctk.CTkEntry(
            target_card,
            height=38,
            placeholder_text="https://example.com"
        )

        self.url_entry.pack(
            fill="x",
            padx=16,
            pady=(0, 14)
        )

        # ----------------------------------------------------
        # LAYERS
        # ----------------------------------------------------

        layers_card = ctk.CTkFrame(
            self.main_scroll,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=CARD_BORDER
        )

        layers_card.pack(
            fill="x",
            padx=18,
            pady=8
        )

        title_row = ctk.CTkFrame(
            layers_card,
            fg_color="transparent"
        )

        title_row.pack(
            fill="x",
            padx=16,
            pady=(12, 5)
        )

        ctk.CTkLabel(
            title_row,
            text="Choose Security Layers",
            font=("Arial", 16, "bold"),
            text_color=TEXT_COLOR
        ).pack(
            side="left"
        )

        ctk.CTkButton(
            title_row,
            text="Select All",
            width=100,
            command=self.select_all
        ).pack(
            side="right",
            padx=(6, 0)
        )

        ctk.CTkButton(
            title_row,
            text="Clear",
            width=75,
            fg_color=DARK_BUTTON,
            hover_color=DARK_BUTTON_HOVER,
            command=self.clear_selection
        ).pack(
            side="right"
        )

        # ----------------------------------------------------
        # LAYER GRID
        # ----------------------------------------------------

        layer_grid = ctk.CTkFrame(
            layers_card,
            fg_color="transparent"
        )

        layer_grid.pack(
            fill="x",
            padx=12,
            pady=(4, 12)
        )

        for index, (
            name,
            descriptions
        ) in enumerate(
            SECURITY_LAYERS.items()
        ):

            card = ctk.CTkFrame(
                layer_grid,
                fg_color="#172033",
                corner_radius=10,
                border_width=1,
                border_color=CARD_BORDER
            )

            card.grid(
                row=index // 2,
                column=index % 2,
                sticky="nsew",
                padx=5,
                pady=5
            )

            ctk.CTkCheckBox(
                card,
                text=name,
                variable=self.layer_vars[name],
                font=("Arial", 13, "bold"),
                text_color=TEXT_COLOR,
                checkbox_width=20,
                checkbox_height=20
            ).pack(
                anchor="w",
                padx=12,
                pady=(12, 7)
            )

            ctk.CTkLabel(
                card,
                text="\n".join(
                    "• " + item
                    for item in descriptions
                ),
                justify="left",
                anchor="w",
                wraplength=390,
                font=("Arial", 11),
                text_color=SECONDARY_TEXT
            ).pack(
                anchor="w",
                padx=12,
                pady=(0, 12)
            )

        layer_grid.grid_columnconfigure(
            0,
            weight=1
        )

        layer_grid.grid_columnconfigure(
            1,
            weight=1
        )

        # ----------------------------------------------------
        # BUTTONS
        # ----------------------------------------------------

        controls = ctk.CTkFrame(
            self.main_scroll,
            fg_color="transparent"
        )

        controls.pack(
            fill="x",
            padx=18,
            pady=8
        )

        self.scan_button = ctk.CTkButton(
            controls,
            text="START LAYER SCAN",
            height=44,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            font=("Arial", 14, "bold"),
            command=self.start_scan
        )

        self.scan_button.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 6)
        )

        self.save_button = ctk.CTkButton(
            controls,
            text="SAVE REPORT",
            height=44,
            width=150,
            fg_color=DARK_BUTTON,
            hover_color=DARK_BUTTON_HOVER,
            command=self.save_report,
            state="disabled"
        )

        self.save_button.pack(
            side="right",
            padx=(6, 0)
        )

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        self.status_label = ctk.CTkLabel(
            self.main_scroll,
            text="Ready",
            font=("Arial", 12),
            text_color=SECONDARY_TEXT
        )

        self.status_label.pack(
            anchor="w",
            padx=22,
            pady=(2, 5)
        )

        # ----------------------------------------------------
        # REPORT CARD
        # ----------------------------------------------------

        report_card = ctk.CTkFrame(
            self.main_scroll,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=CARD_BORDER
        )

        report_card.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=(4, 20)
        )

        ctk.CTkLabel(
            report_card,
            text="Scan Report",
            font=("Arial", 17, "bold"),
            text_color=TEXT_COLOR
        ).pack(
            anchor="w",
            padx=15,
            pady=(12, 5)
        )

        self.output = ctk.CTkTextbox(
            report_card,
            height=430,
            corner_radius=8,
            fg_color="#080d18",
            text_color=TEXT_COLOR,
            font=("Consolas", 11),
            wrap="word"
        )

        self.output.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=(0, 12)
        )

        self.output.insert(
            "1.0",
            "Select the layers you want to assess,\n"
            "enter an authorized target website,\n"
            "and click START LAYER SCAN.\n\n"
            "Your complete report will appear here "
            "after the scan finishes."
        )


    # ========================================================
    # SELECT ALL
    # ========================================================

    def go_back(self):

        if self.scanning or not self.on_back:
            return

        self.on_back()

    def select_all(self):

        for variable in self.layer_vars.values():

            variable.set(True)


    # ========================================================
    # CLEAR
    # ========================================================

    def clear_selection(self):

        for variable in self.layer_vars.values():

            variable.set(False)


    # ========================================================
    # START SCAN
    # ========================================================

    def start_scan(self):

        if self.scanning:

            return

        try:

            target = normalize_url(
                self.url_entry.get()
            )

        except ValueError as exc:

            messagebox.showerror(
                "Invalid Target",
                str(exc)
            )

            return

        selected_layers = [

            name

            for name, variable
            in self.layer_vars.items()

            if variable.get()
        ]

        if not selected_layers:

            messagebox.showwarning(
                "No Layers Selected",
                "Please select at least one security layer."
            )

            return

        authorized = messagebox.askyesno(
            "Authorization Required",
            "Confirm that you own this website or "
            "have explicit permission to perform these "
            "security checks.\n\n"
            "Only continue if you are authorized."
        )

        if not authorized:

            return

        # ----------------------------------------------------
        # UI STATE
        # ----------------------------------------------------

        self.scanning = True

        if self.on_scan_state:
            self.on_scan_state(True)

        self.scan_button.configure(
            state="disabled",
            text="SCANNING..."
        )

        if getattr(self, "back_button", None):
            self.back_button.configure(state="disabled")

        self.save_button.configure(
            state="disabled"
        )

        self.status_label.configure(
            text=(
                "Scanning selected security layers..."
            ),
            text_color=ORANGE
        )

        # ----------------------------------------------------
        # CLEAR OLD REPORT
        # ----------------------------------------------------

        self.output.delete(
            "1.0",
            "end"
        )

        self.output.insert(
            "end",
            "WEB APPLICATION SECURITY TOOLKIT\n"
            "SECURITY LAYER SCAN\n"
            "\n"
            f"Target:\n{target}\n\n"
            "Selected Layers:\n"
        )

        for layer in selected_layers:

            self.output.insert(
                "end",
                f"  • {layer}\n"
            )

        self.output.insert(
            "end",
            "\n"
            "Scan in progress...\n"
            "Please wait.\n"
        )

        # ----------------------------------------------------
        # THREAD
        # ----------------------------------------------------

        thread = threading.Thread(
            target=self.scan_worker,
            args=(
                target,
                selected_layers
            ),
            daemon=True
        )

        thread.start()


    # ========================================================
    # WORKER
    # ========================================================

    def scan_worker(
        self,
        target,
        selected_layers
    ):

        try:

            results = scan_selected_layers(
                target,
                selected_layers
            )

            report = format_results(
                results
            )

            self.after(
                0,
                lambda: self.scan_finished(
                    results,
                    report
                )
            )

        except Exception as exc:

            error_text = str(exc)

            self.after(
                0,
                lambda: self.scan_failed(
                    error_text
                )
            )


    # ========================================================
    # SCAN FINISHED
    # ========================================================

    def scan_finished(
        self,
        results,
        report
    ):

        self.scanning = False

        if self.on_scan_state:
            self.on_scan_state(False)

        self.last_results = results

        # ----------------------------------------------------
        # RESTORE BUTTONS
        # ----------------------------------------------------

        self.scan_button.configure(
            state="normal",
            text="START LAYER SCAN"
        )

        self.save_button.configure(
            state="normal"
        )

        if getattr(self, "back_button", None):
            self.back_button.configure(state="normal")

        self.status_label.configure(
            text=(
                "Scan completed successfully. "
                "Report is displayed below."
            ),
            text_color=GREEN
        )

        # ----------------------------------------------------
        # SHOW FULL REPORT INSIDE GUI
        # ----------------------------------------------------

        self.output.delete(
            "1.0",
            "end"
        )

        self.output.insert(
            "1.0",
            report
        )

        # Automatically scroll report to top
        self.output.see(
            "1.0"
        )

        # Scroll whole page back to report area
        self.after(
            100,
            self.scroll_to_report
        )


    # ========================================================
    # SCROLL TO REPORT
    # ========================================================

    def scroll_to_report(self):

        try:

            self.main_scroll._parent_canvas.yview_moveto(
                1.0
            )

        except Exception:

            pass


    # ========================================================
    # SCAN FAILED
    # ========================================================

    def scan_failed(
        self,
        error_text
    ):

        self.scanning = False

        if self.on_scan_state:
            self.on_scan_state(False)

        self.scan_button.configure(
            state="normal",
            text="START LAYER SCAN"
        )

        if getattr(self, "back_button", None):
            self.back_button.configure(state="normal")

        self.status_label.configure(
            text="Scan failed.",
            text_color=RED
        )

        self.output.delete(
            "1.0",
            "end"
        )

        self.output.insert(
            "1.0",
            "SCAN ERROR\n"
            "===========\n\n"
            f"{error_text}"
        )

        messagebox.showerror(
            "Scan Error",
            error_text
        )


    # ========================================================
    # SAVE REPORT
    # ========================================================

    def save_report(self):

        if not self.last_results:

            messagebox.showwarning(
                "No Report",
                "Run a scan before saving a report."
            )

            return

        default_name = (
            "layer_scan_"
            + datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
            + ".txt"
        )

        path = filedialog.asksaveasfilename(

            title="Save Layer Scan Report",

            defaultextension=".txt",

            initialfile=default_name,

            filetypes=[
                (
                    "Text Report",
                    "*.txt"
                )
            ]
        )

        if not path:

            return

        try:

            report = format_results(
                self.last_results
            )

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as report_file:

                report_file.write(
                    report
                )

            messagebox.showinfo(
                "Report Saved",
                f"Report saved successfully:\n\n{path}"
            )

        except OSError as exc:

            messagebox.showerror(
                "Save Error",
                f"Could not save report:\n\n{exc}"
            )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    ctk.set_appearance_mode(
        "dark"
    )

    ctk.set_default_color_theme(
        "blue"
    )

    root = ctk.CTk()
    root.title(APP_TITLE)
    root.geometry("1100x780")
    root.minsize(800, 600)

    app = LayerScannerApp(root)
    app.pack(fill="both", expand=True)

    root.mainloop()
