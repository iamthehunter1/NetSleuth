import customtkinter as ctk
import csv
import json
import os
import re
from tkinter import filedialog, ttk
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import ipaddress
import socket
import threading
from pathlib import Path
import ssl
from datetime import datetime, timezone
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")
PURPLE = "#8B5CF6"
PURPLE_HOVER = "#7C3AED"
BG_COLOR = "#111018"
PANEL_COLOR = "#1C1A27"
TEXT_COLOR = "#F4F0FF"
MUTED_COLOR = "#A6A0B8"
def inspect_url(value):
    value = value.strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("URL cannot contain spaces or control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid URL: {error}") from error
    if parsed.scheme not in ("http", "https") or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")
    hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if len(hostname) > 235 or any(
        not part or len(part) > 63 for part in hostname.split(".")
    ):
        raise ValueError("Invalid hostname.")
    warnings = []
    if parsed.scheme == "http":
        warnings.append("HTTP does not encrypt the connection")
    if "@" in parsed.netloc:
        warnings.append("@ in the URL can disguise the destination host")
    if len(value) > 200:
        warnings.append("Unusually long URL")
    try:
        ipaddress.ip_address(hostname)
        warnings.append("Host is an IP address, not a domain name.")
    except ValueError:
        pass
    if parsed.fragment:
        warnings.append("URL contains a fragment (#section).")
    return {
        "url": value,
        "scheme": parsed.scheme,
        "host": hostname,
        "port": port or (443 if parsed.scheme == "https" else 80),
        "path": parsed.path or "/",
        "warnings": warnings,
    }
def calculate_risk(warnings):
    score = 0
    for warning in warnings:
        warning_lower = warning.lower()
        if "disguise the destination" in warning_lower:
            score += 30
        elif "does not encrypt" in warning_lower:
            score += 25
        elif "embedded credentials" in warning_lower:
            score += 25
        elif "ip address" in warning_lower:
            score += 15
        elif "unusually long" in warning_lower:
            score += 10
        elif "fragment " in warning_lower:
            score += 5
    score = min(score, 100)
    if score >= 60:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level
def inspect_ssl_certificate(hostname, port=443):
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port), timeout=7) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=hostname
            ) as tls_socket:
                certificate = tls_socket.getpeercert()
                tls_version = tls_socket.version()
                cipher_info = tls_socket.cipher()
        subject_parts = []
        for group in certificate.get("subject", ()):
            for key, value in group:
                subject_parts.append(f"{key}={value}")
        subject = ", ".join(subject_parts) or "Not provided"
        issuer_parts = []
        for group in certificate.get("issuer", ()):
            for key, value in group:
                issuer_parts.append(f"{key}={value}")
        issuer = ", ".join(issuer_parts) or "Not provided"
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(certificate["notBefore"]),
            tz=timezone.utc,
        )
        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(certificate["notAfter"]),
            tz=timezone.utc,
        )
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).total_seconds() / 86400
        if now < not_before:
            expiry_status = "NOT YET VALID"
        elif days_remaining < 0:
            expiry_status = "EXPIRED"
        elif days_remaining <= 14:
            expiry_status = "EXPIRING SOON"
        else:
            expiry_status = "VALID"
        san_entries = certificate.get("subjectAltName", ())
        san_lines = [
            f"    {kind}: {value}"
            for kind, value in san_entries
        ]
        cipher_name = cipher_info[0] if cipher_info else "Unknown"
        cipher_bits = cipher_info[2] if cipher_info else "Unknown"
        report = [
            "=" * 54,
            "NETSLEUTH - SSL/TLS CERTIFICATE REPORT",
            "=" * 54,
            f"Hostname:       {hostname}",
            f"Port:           {port}",
            f"TLS Version:    {tls_version or 'Unknown'}",
            f"Cipher:         {cipher_name}",
            f"Cipher Bits:    {cipher_bits}",
            "Verification:   PASSED",
            "",
            "CERTIFICATE DETAILS",
            "-" * 54,
            f"Subject:        {subject}",
            f"Issuer:         {issuer}",
            f"Valid From:     {not_before:%Y-%m-%d %H:%M:%S UTC}",
            f"Expires At:     {not_after:%Y-%m-%d %H:%M:%S UTC}",
            f"Days Remaining: {max(0, int(days_remaining))}",
            f"Expiry Status:  {expiry_status}",
            "",
            "SUBJECT ALTERNATIVE NAMES (SAN)",
            "-" * 54,
        ]
        report.extend(san_lines or ["No SAN entries provided."])
        report.extend([
            "",
            "CERTIFICATE VERIFICATION",
            "-" * 54,
            "The certificate chain and hostname passed",
            "the system's configured TLS verification checks.",
            "",
            "A valid certificate does not guarantee that",
            "a website is trustworthy or free of malicious content.",
            "=" * 54,
        ])
        return "\n".join(report)
    except ssl.SSLCertVerificationError as error:
        return (
            "=" * 54
            + "\nTLS CERTIFICATE VERIFICATION FAILED\n"
            + "=" * 54
            + f"\nHostname: {hostname}"
            + f"\nReason: {error}"
            + "\n\nPossible causes include an expired certificate, "
            "a hostname mismatch, an untrusted issuer, or an "
            "incomplete certificate chain."
        )
    except (socket.timeout, TimeoutError):
        return (
            f"Connection timed out while checking {hostname}:{port}.\n"
            "The server may be slow, unreachable, or blocking connections."
        )
    except ConnectionRefusedError:
        return (
            f"Connection refused by {hostname}:{port}.\n"
            "The server may not accept HTTPS connections on this port."
        )
    except (socket.gaierror, OSError, ssl.SSLError) as error:
        return (
            f"Could not inspect the TLS certificate for {hostname}.\n"
            f"Error: {error}"
        )
def inspect_security_headers(value):
    value = value.strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("URL cannot contain spaces or control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Enter a valid HTTP or HTTPS URL.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded credentials are not supported.")
        parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid URL: {error}") from error
    request = Request(
        value,
        headers={
            "User-Agent": "NetSleuth/1.0",
            "Accept": "*/*",
        },
        method="GET",
    )
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    except (URLError, TimeoutError, socket.timeout, OSError) as error:
        raise RuntimeError(f"Could not connect to website: {error}") from error
    with response:
        status_code = response.status
        final_url = response.geturl()
        headers = response.headers
        final_scheme = urlsplit(final_url).scheme.lower()
        checks = [
            (
                "Strict-Transport-Security",
                "HIGH",
                "Helps enforce HTTPS connections.",
                final_scheme == "https",
            ),
            (
                "Content-Security-Policy",
                "HIGH",
                "Restricts the sources of scripts and other page resources.",
                True,
            ),
            (
                "X-Content-Type-Options",
                "MEDIUM",
                "Helps prevent browsers from guessing content types.",
                True,
            ),
            (
                "X-Frame-Options",
                "MEDIUM",
                "Helps control whether the page can be embedded in frames.",
                True,
            ),
            (
                "Referrer-Policy",
                "LOW",
                "Controls how much referrer information browsers send.",
                True,
            ),
            (
                "Permissions-Policy",
                "LOW",
                "Controls access to selected browser features.",
                True,
            ),
        ]
        findings = []
        for name, severity, description, applicable in checks:
            header_value = headers.get(name)
            if not applicable:
                status = "NOT APPLICABLE"
            elif header_value:
                status = "PRESENT"
            else:
                status = "MISSING"
            findings.append({
                "name": name,
                "severity": severity,
                "description": description,
                "status": status,
                "value": header_value.strip() if header_value else "",
            })
        return {
            "requested_url": value,
            "final_url": final_url,
            "status_code": status_code,
            "findings": findings,
        }
def enumerate_subdomains(value, resolve_dns=False):
    value = value.strip().lower().rstrip(".")
    if not value:
        raise ValueError("Enter a domain such as example.com.")
    if (
        "://" in value
        or "/" in value
        or "@" in value
        or ":" in value
        or any(char.isspace() for char in value)
    ):
        raise ValueError("Enter a domain only, without a scheme or path.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Invalid domain name.") from error
    if len(value) > 253 or "." not in value:
        raise ValueError("Enter a fully qualified domain such as example.com.")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) 
        for label in labels
    ):
        raise ValueError("Invalid domain name.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")
    request = Request(
        "https://crt.sh/?q=%25." + value + "&output=json",
        headers={
            "User-Agent": "NetSleuth/1.0",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            payload = response.read(8 * 1024 * 1024 + 1)
    except (URLError, TimeoutError, socket.timeout, OSError) as error:
        raise RuntimeError(
            f"Certificate Transparency lookup failed: {error}"
        ) from error
    if len(payload) > 8 * 1024 * 1024:
        raise RuntimeError(
            "The response was too large. Try a more specific domain."
        )
    try:
        records = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            "The Certificate Transparency service returned invalid data."
        ) from error
    if not isinstance(records, list):
        raise RuntimeError(
            "Unexpected response from Certificate Transparency service."
        )
    found = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        names = record.get("name_value", "")
        if not isinstance(names, str):
            continue
        for candidate in names.splitlines():
            candidate = candidate.strip().lower().rstrip(".")
            if candidate.startswith("*."):
                candidate = candidate[2:]
            try:
                candidate = candidate.encode("idna").decode("ascii")
            except UnicodeError:
                continue
            if candidate == value or candidate.endswith("." + value):
                if len(candidate) <= 253 and all(
                    label
                    and len(label) <= 63
                    and re.fullmatch(
                        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                        label,
                    )
                    for label in candidate.split(".")
                ):
                    found.add(candidate)
    results = []
    for hostname in sorted(found):
        addresses = []
        status = "Not checked"
        if resolve_dns:
            try:
                addresses = sorted({
                    item[4][0]
                    for item in socket.getaddrinfo(
                        hostname, None, type=socket.SOCK_STREAM
                    )
                })
                status = "Resolves" if addresses else "No records"
            except (socket.gaierror, OSError):
                status = "No records"
        results.append({
            "subdomain": hostname,
            "dns_status": status,
            "addresses": ", ".join(addresses),
            "source": "crt.sh / Certificate Transparency",
        })
    return value, results
from ipinfo_api import (
    api_key_path, load_ipinfo_key, save_ipinfo_key,
    remove_ipinfo_key, validate_ipinfo_key, lookup_ipinfo,
)
class NetSleuth(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NetSleuth")
        self.geometry("1000x680")
        self.minsize(780, 560)
        self.configure(fg_color=BG_COLOR)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.sidebar = ctk.CTkFrame(
            self,
            width=205,
            corner_radius=0,
            fg_color="#171521",
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        ctk.CTkLabel(
            self.sidebar,
            text="◈ NetSleuth",
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color=PURPLE,
        ).pack(padx=18, pady=(28, 4), anchor="w")
        ctk.CTkLabel(
            self.sidebar,
            text="SECURITY INTELLIGENCE",
            font=ctk.CTkFont(size=10),
            text_color=MUTED_COLOR,
        ).pack(padx=20, pady=(0, 30), anchor="w")
        self.pages = {}
        self.content = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=BG_COLOR,
        )
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(1, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.header = ctk.CTkFrame(
            self.content,
            fg_color="transparent",
        )
        self.header.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=28,
            pady=(24, 10),
        )
        self.page_title = ctk.CTkLabel(
            self.header,
            text="URL Scanner",
            font=ctk.CTkFont(size=27, weight="bold"),
            text_color=TEXT_COLOR,
        )
        self.page_title.pack(anchor="w")
        self.page_subtitle = ctk.CTkLabel(
            self.header,
            text="Inspect URLs, warnings and hostname information.",
            text_color=MUTED_COLOR,
        )
        self.page_subtitle.pack(anchor="w", pady=(4, 0))
        self.page_area = ctk.CTkFrame(
            self.content,
            fg_color="transparent",
        )
        self.page_area.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=25,
            pady=(8, 20),
        )
        self.page_area.grid_rowconfigure(0, weight=1)
        self.page_area.grid_columnconfigure(0, weight=1)
        self.create_url_page()
        self.create_dns_page()
        self.create_ssl_page()
        self.create_headers_page()
        self.create_subdomain_page()
        self.create_ipinfo_page()
        self.nav_buttons = {}
        for name, label in [
            ("URL Scanner", "URL Scanner"),
            ("DNS Lookup", "DNS Lookup"),
            ("SSL Checker", "SSL Checker"),
            ("HTTP Headers", "HTTP Headers"),
            ("Subdomain Enumerator", "Subdomain Enumerator"),
            ("IPinfo Lookup", "IPinfo Lookup"),
        ]:
            button = ctk.CTkButton(
                self.sidebar,
                text=label,
                anchor="w",
                height=43,
                corner_radius=9,
                fg_color="transparent",
                hover_color="#302744",
                text_color=TEXT_COLOR,
                command=lambda page=name: self.show_page(page),
            )
            button.pack(fill="x", padx=12, pady=4)
            self.nav_buttons[name] = button
        ctk.CTkLabel(
            self.sidebar,
            text="NETSLEUTH",
            text_color=MUTED_COLOR,
            font=ctk.CTkFont(size=10),
        ).pack(side="bottom", padx=14, pady=18)
        self.show_page("URL Scanner")
    def create_url_page(self):
        page = ctk.CTkFrame(self.page_area, fg_color="transparent")
        self.pages["URL Scanner"] = page
        ctk.CTkLabel(
            page,
            text="Enter a URL to investigate",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", pady=(4, 10))
        self.url_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="https://example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR,
        )
        self.url_entry.pack(fill="x", pady=(0, 10))
        self.url_entry.bind("<Return>", lambda event: self.analyze_url())
        ctk.CTkButton(
            page,
            text="Analyze URL",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.analyze_url,
        ).pack(anchor="w", pady=(0, 16))
        self.results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148",
        )
        self.results.pack(fill="both", expand=True)
        self.results.insert(
            "end",
            "Welcome to NetSleuth\n\n"
            "Enter a URL to inspect its components and warnings.\n"
            "DNS address resolution runs after URL inspection.\n\n"
            "Risk indicators are heuristic checks, not proof "
            "that a website is malicious or safe.\n",
        )
    def create_dns_page(self):
        page = ctk.CTkFrame(self.page_area, fg_color="transparent")
        self.pages["DNS Lookup"] = page
        ctk.CTkLabel(
            page,
            text="DNS Record Lookup",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            page,
            text="Look up IP addresses for a hostname.",
            text_color=MUTED_COLOR,
        ).pack(anchor="w", pady=(0, 14))
        self.dns_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR,
        )
        self.dns_entry.pack(fill="x", pady=(0, 10))
        self.dns_entry.bind("<Return>", lambda event: self.lookup_dns())
        ctk.CTkButton(
            page,
            text="Look Up Hostname",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.lookup_dns,
        ).pack(anchor="w", pady=(0, 16))
        self.dns_results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148",
        )
        self.dns_results.pack(fill="both", expand=True)
        self.dns_results.insert(
            "end",
            "DNS lookup ready.\n\n"
            "Enter a hostname above to resolve its IP addresses.",
        )
    def create_ssl_page(self):
        page = ctk.CTkFrame(self.page_area, fg_color="transparent")
        self.pages["SSL Checker"] = page
        ctk.CTkLabel(
            page,
            text="SSL/TLS Certificate Checker",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            page,
            text="Inspect HTTPS certificates, expiry dates and TLS versions.",
            text_color=MUTED_COLOR,
        ).pack(anchor="w", pady=(0, 14))
        self.ssl_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR,
        )
        self.ssl_entry.pack(fill="x", pady=(0, 10))
        self.ssl_entry.bind(
            "<Return>",
            lambda event: self.check_ssl_certificate(),
        )
        self.ssl_check_button = ctk.CTkButton(
            page,
            text="Check Certificate",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.check_ssl_certificate,
        )
        self.ssl_check_button.pack(anchor="w", pady=(0, 16))
        self.ssl_results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148",
        )
        self.ssl_results.pack(fill="both", expand=True)
        self.ssl_results.insert(
            "end",
            "SSL/TLS certificate checker ready.\n\n"
            "Enter a hostname such as example.com.\n\n"
            "Internet access is required.",
        )
    def create_headers_page(self):
        page = ctk.CTkFrame(self.page_area, fg_color="transparent")
        self.pages["HTTP Headers"] = page
        ctk.CTkLabel(
            page,
            text="HTTP Security Headers Checker",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            page,
            text="Check a website's response for common security headers.",
            text_color=MUTED_COLOR,
        ).pack(anchor="w", pady=(0, 14))
        self.headers_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="https://example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR,
        )
        self.headers_entry.pack(fill="x", pady=(0, 10))
        self.headers_entry.bind(
            "<Return>",
            lambda event: self.check_security_headers(),
        )
        self.headers_check_button = ctk.CTkButton(
            page,
            text="Check Security Headers",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.check_security_headers,
        )
        self.headers_check_button.pack(anchor="w", pady=(0, 16))
        self.headers_results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148",
        )
        self.headers_results.pack(fill="both", expand=True)
        self.headers_results.insert(
            "end",
            "HTTP security headers checker ready.\n\n"
            "Enter a website URL to inspect its response headers.\n\n"
            "The report identifies missing headers and explains "
            "their purpose. Missing headers alone do not prove "
            "a website is vulnerable.",
        )
    def create_subdomain_page(self):
        page = ctk.CTkFrame(self.page_area, fg_color="transparent")
        self.pages["Subdomain Enumerator"] = page
        ctk.CTkLabel(
            page,
            text="Passive Subdomain Enumeration",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            page,
            text="Discover hostnames from public Certificate Transparency logs.",
            text_color=MUTED_COLOR,
        ).pack(anchor="w", pady=(0, 12))
        self.subdomain_entry = ctk.CTkEntry(
            page,
            height=42,
            placeholder_text="example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR,
        )
        self.subdomain_entry.pack(fill="x", pady=(0, 9))
        self.subdomain_entry.bind(
            "<Return>",
            lambda event: self.start_subdomain_scan(),
        )
        controls = ctk.CTkFrame(page, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 12))
        self.subdomain_resolve_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            controls,
            text="Resolve discovered hosts with DNS",
            variable=self.subdomain_resolve_var,
            text_color=TEXT_COLOR,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
        ).pack(side="left", padx=(0, 12))
        self.subdomain_scan_button = ctk.CTkButton(
            controls,
            text="Enumerate",
            height=38,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.start_subdomain_scan,
        )
        self.subdomain_scan_button.pack(side="left", padx=(0, 8))
        self.subdomain_export_button = ctk.CTkButton(
            controls,
            text="Export CSV",
            height=38,
            fg_color="#302744",
            hover_color="#403358",
            command=self.export_subdomains,
            state="disabled",
        )
        self.subdomain_export_button.pack(side="left")
        self.subdomain_status = ctk.CTkLabel(
            page,
            text="Ready",
            text_color=MUTED_COLOR,
            anchor="w",
        )
        self.subdomain_status.pack(fill="x", pady=(0, 8))
        table_frame = ctk.CTkFrame(
            page,
            fg_color=PANEL_COLOR,
            corner_radius=8,
        )
        table_frame.pack(fill="both", expand=True)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "NetSleuth.Treeview",
            background=PANEL_COLOR,
            foreground=TEXT_COLOR,
            fieldbackground=PANEL_COLOR,
            rowheight=27,
            borderwidth=0,
        )
        style.configure(
            "NetSleuth.Treeview.Heading",
            background="#302744",
            foreground=TEXT_COLOR,
            relief="flat",
            borderwidth=0,
            padding=(8, 8),
        )
        style.map(
            "NetSleuth.Treeview.Heading",
            background=[
                ("active", "#242033"),
                ("!active", "#242033"),
    ],
            foreground=[
                ("active", "#682BDA"),
                ("!active", "#8122EE"),
    ],
)
        self.subdomain_tree = ttk.Treeview(
            table_frame,
            columns=("host", "dns", "addresses"),
            show="headings",
            style="NetSleuth.Treeview",
        )
        self.subdomain_tree.heading("host", text="Subdomain")
        self.subdomain_tree.heading("dns", text="DNS Status")
        self.subdomain_tree.heading("addresses", text="IP Addresses")
        self.subdomain_tree.column("host", width=240, minwidth=150)
        self.subdomain_tree.column(
            "dns", width=110, minwidth=90, anchor="center"
        )
        self.subdomain_tree.column(
            "addresses", width=250, minwidth=150
        )
        style.configure(
            "NetSleuth.Vertical.TScrollbar",
            background="#302744",
            troughcolor=PANEL_COLOR,
            bordercolor=PANEL_COLOR,
            arrowcolor=TEXT_COLOR,
        )
        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.subdomain_tree.yview,
            style="NetSleuth.Vertical.TScrollbar",
        )
        self.subdomain_tree.configure(yscrollcommand=scrollbar.set)
        self.subdomain_tree.grid(
            row=0, column=0, sticky="nsew", padx=(8, 0), pady=8
        )
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)
        self.subdomain_results = []
    def create_ipinfo_page(self):
        page = ctk.CTkFrame(self.page_area, fg_color="transparent")
        self.pages["IPinfo Lookup"] = page
        ctk.CTkLabel(page, text="IPinfo API & IP Lookup", font=ctk.CTkFont(size=19, weight="bold"), text_color=TEXT_COLOR).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(page, text="Add your own IPinfo token, validate it, and save it on this computer.", text_color=MUTED_COLOR).pack(anchor="w", pady=(0, 12))
        self.ipinfo_key_entry = ctk.CTkEntry(page, height=40, placeholder_text="IPinfo API token", show="*", border_color=PURPLE, fg_color=PANEL_COLOR)
        self.ipinfo_key_entry.pack(fill="x", pady=(0, 8))
        key_buttons = ctk.CTkFrame(page, fg_color="transparent")
        key_buttons.pack(fill="x", pady=(0, 12))
        ctk.CTkButton(key_buttons, text="Validate & Save Key", fg_color=PURPLE, hover_color=PURPLE_HOVER, command=self.validate_and_save_ipinfo).pack(side="left", padx=(0, 8))
        ctk.CTkButton(key_buttons, text="Delete Saved Key", fg_color="#302744", hover_color="#403358", command=self.delete_saved_ipinfo).pack(side="left")
        self.ipinfo_status = ctk.CTkLabel(page, text="No token loaded.", text_color=MUTED_COLOR, anchor="w", wraplength=650)
        self.ipinfo_status.pack(fill="x", pady=(0, 10))
        self.ipinfo_ip_entry = ctk.CTkEntry(page, height=40, placeholder_text="IP address (leave blank to look up your public IP)", border_color=PURPLE, fg_color=PANEL_COLOR)
        self.ipinfo_ip_entry.pack(fill="x", pady=(0, 8))
        self.ipinfo_lookup_button = ctk.CTkButton(page, text="Look Up IP", fg_color=PURPLE, hover_color=PURPLE_HOVER, command=self.lookup_ipinfo)
        self.ipinfo_lookup_button.pack(anchor="w", pady=(0, 12))
        self.ipinfo_results = ctk.CTkTextbox(page, wrap="word", font=ctk.CTkFont(family="Consolas", size=12), fg_color=PANEL_COLOR, border_width=1, border_color="#393148")
        self.ipinfo_results.pack(fill="both", expand=True)
        self.ipinfo_results.insert("end", "IPinfo lookup ready\nGet a token at https://ipinfo.io/\n\nThe token is stored locally in the application-data folder This first version uses a local JSON file; it is not encrypted, so only use it on a trusted Windows account.")
        saved_key = load_ipinfo_key()
        if saved_key:
            self.ipinfo_key_entry.insert(0, saved_key)
            self.ipinfo_status.configure(text=f"Saved token loaded. File: {api_key_path()}")
    def validate_and_save_ipinfo(self):
        api_key = self.ipinfo_key_entry.get().strip()
        if not api_key:
            self.ipinfo_status.configure(text="Enter your IPinfo token first.", text_color="#F87171")
            return
        self.ipinfo_status.configure(text="Validating token...", text_color=MUTED_COLOR)
        def worker():
            valid, message = validate_ipinfo_key(api_key)
            saved_path = None
            if valid:
                try:
                    save_ipinfo_key(api_key)
                    saved_path = api_key_path()
                except (OSError, ValueError):
                    valid = False
                    message = "Token validated, but saving it locally failed."
            self.after(0, self.finish_ipinfo_save, valid, message, str(saved_path) if saved_path else "")
        threading.Thread(target=worker, daemon=True).start()
    def finish_ipinfo_save(self, valid, message, saved_path):
        if valid:
            self.ipinfo_status.configure(text=f"{message} Saved locally at: {saved_path}", text_color="#4ADE80")
        else:
            self.ipinfo_status.configure(text=message, text_color="#F87171")
    def delete_saved_ipinfo(self):
        if remove_ipinfo_key():
            self.ipinfo_key_entry.delete(0, "end")
            self.ipinfo_status.configure(text="Saved IPinfo token deleted.", text_color=TEXT_COLOR)
        else:
            self.ipinfo_status.configure(text="No saved token found, or deletion failed.", text_color=MUTED_COLOR)
    def lookup_ipinfo(self):
        api_key = load_ipinfo_key()
        if not api_key:
            self.ipinfo_status.configure(text="Save a valid IPinfo token first.", text_color="#F87171")
            return
        ip_value = self.ipinfo_ip_entry.get().strip()
        if ip_value:
            try:
                ip_value = str(ipaddress.ip_address(ip_value))
            except ValueError:
                self.ipinfo_results.delete("1.0", "end")
                self.ipinfo_results.insert("end", "Enter a valid IPv4 or IPv6 address, or leave blank for your public IP.")
                return
        self.ipinfo_lookup_button.configure(state="disabled")
        self.ipinfo_results.delete("1.0", "end")
        self.ipinfo_results.insert("end", "Looking up IP information...")
        def worker():
            try:
                data = lookup_ipinfo(api_key, ip_value)
                fields = (("IP Address", "ip"), ("Hostname", "hostname"), ("City", "city"), ("Region", "region"), ("Country", "country"), ("Location", "loc"), ("Organization", "org"), ("Postal Code", "postal"), ("Timezone", "timezone"))
                lines = ["IPINFO LOOKUP REPORT", "=" * 38]
                for label, key in fields:
                    if data.get(key):
                        lines.append(f"{label}: {data[key]}")
                report = "\n".join(lines)
            except HTTPError as error:
                report = f"IPinfo lookup failed with HTTP status {error.code}."
            except (URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError):
                report = "IPinfo lookup failed. Check your connection and saved token."
            self.after(0, self.finish_ipinfo_lookup, report)
        threading.Thread(target=worker, daemon=True).start()
    def finish_ipinfo_lookup(self, report):
        self.ipinfo_results.delete("1.0", "end")
        self.ipinfo_results.insert("end", report)
        self.ipinfo_lookup_button.configure(state="normal")
    def start_subdomain_scan(self):
        domain = self.subdomain_entry.get().strip()
        resolve_dns = self.subdomain_resolve_var.get()
        self.subdomain_scan_button.configure(state="disabled")
        self.subdomain_export_button.configure(state="disabled")
        self.subdomain_status.configure(
            text="Querying public Certificate Transparency records..."
        )
        for item in self.subdomain_tree.get_children():
            self.subdomain_tree.delete(item)
        self.subdomain_results = []
        def worker():
            try:
                normalized_domain, results = enumerate_subdomains(
                    domain, resolve_dns
                )
                message = None
            except (ValueError, RuntimeError, UnicodeError) as error:
                normalized_domain, results, message = "", [], str(error)
            except Exception as error:
                normalized_domain, results, message = (
                    "",
                    [],
                    f"Unexpected error: {error}",
                )
            try:
                self.after(
                    0,
                    self.show_subdomain_results,
                    normalized_domain,
                    results,
                    message,
                )
            except RuntimeError:
                pass
        threading.Thread(target=worker, daemon=True).start()
    def show_subdomain_results(self, domain, results, error):
        self.subdomain_scan_button.configure(state="normal")
        if error:
            self.subdomain_status.configure(text=f"Lookup failed: {error}")
            return
        self.subdomain_results = results
        for result in results:
            self.subdomain_tree.insert(
                "",
                "end",
                values=(
                    result["subdomain"],
                    result["dns_status"],
                    result["addresses"],
                ),
            )
        self.subdomain_status.configure(
            text=f"{len(results)} unique hostnames found for {domain} | Source: crt.sh"
        )
        self.subdomain_export_button.configure(
            state="normal" if results else "disabled"
        )
    def export_subdomains(self):
        if not self.subdomain_results:
            return
        path = filedialog.asksaveasfilename(
            title="Export subdomain results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=(
                        "subdomain",
                        "dns_status",
                        "addresses",
                        "source",
                    ),
                )
                writer.writeheader()
                writer.writerows(self.subdomain_results)
            self.subdomain_status.configure(
                text=f"Exported {len(self.subdomain_results)} results."
            )
        except OSError as error:
            self.subdomain_status.configure(
                text=f"CSV export failed: {error}"
            )
    def show_page(self, page_name):
        for page in self.pages.values():
            page.grid_forget()
        self.pages[page_name].grid(
            row=0,
            column=0,
            sticky="nsew",
        )
        self.page_title.configure(text=page_name)
        subtitles = {
            "URL Scanner": "Inspect URLs, warnings and hostname information.",
            "DNS Lookup": "Resolve a hostname to its IP addresses.",
            "SSL Checker": "Inspect HTTPS certificates and TLS connections.",
            "HTTP Headers": "Inspect HTTP responses for security headers.",
            "Subdomain Enumerator": "Discover hostnames from public certificate records.",
            "IPinfo Lookup": "Manage your IPinfo token and look up IP address details.",
        }
        self.page_subtitle.configure(text=subtitles[page_name])
        for name, button in self.nav_buttons.items():
            button.configure(
                fg_color=PURPLE if name == page_name else "transparent"
            )
    def analyze_url(self):
        value = self.url_entry.get()
        try:
            info = inspect_url(value)
        except (ValueError, UnicodeError) as error:
            self.results.delete("1.0", "end")
            self.results.insert("end", f"URL inspection failed:\n{error}")
            return
        score, level = calculate_risk(info["warnings"])
        report = [
            "URL INSPECTION REPORT",
            "=" * 38,
            f"Time: {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"URL: {info['url']}",
            "",
            f"Risk score: {score}/100 ({level})",
            "",
            "PARSED COMPONENTS",
            "-" * 38,
            f"Scheme: {info['scheme']}",
            f"Host:   {info['host']}",
            f"Port:   {info['port']}",
            f"Path:   {info['path']}",
            "",
            "WARNINGS",
            "-" * 38,
        ]
        if info["warnings"]:
            report.extend(
                f"[!] {warning}" for warning in info["warnings"]
            )
        else:
            report.append("No configured warnings detected")
        report.extend([
            "",
            "DNS ADDRESS LOOKUP",
            "-" * 38,
            "Resolving hostname...",
        ])
        self.results.delete("1.0", "end")
        self.results.insert("end", "\n".join(report))
        threading.Thread(
            target=self.resolve_dns,
            args=(info["host"],),
            daemon=True,
        ).start()
    def resolve_dns(self, hostname):
        try:
            addresses = sorted({
                result[4][0]
                for result in socket.getaddrinfo(
                    hostname, None, type=socket.SOCK_STREAM
                )
            })
            message = "\n".join(addresses) if addresses else "No addresses returned"
        except OSError as error:
            message = f"DNS lookup failed: {error}"
        self.after(0, self.append_dns_result, message)
    def append_dns_result(self, message):
        current = self.results.get("1.0", "end").rstrip()
        current = current.replace("Resolving hostname...", message)
        self.results.delete("1.0", "end")
        self.results.insert("end", current)
    def lookup_dns(self):
        hostname = self.dns_entry.get().strip().rstrip(".")
        if (
            not hostname
            or any(char.isspace() for char in hostname)
            or "://" in hostname
            or "/" in hostname
            or "@" in hostname
        ):
            self.dns_results.delete("1.0", "end")
            self.dns_results.insert(
                "end", "Enter a hostname such as example.com"
            )
            return
        self.dns_results.delete("1.0", "end")
        self.dns_results.insert("end", "Resolving hostname...")
        def worker():
            try:
                addresses = sorted({
                    result[4][0]
                    for result in socket.getaddrinfo(
                        hostname, None, type=socket.SOCK_STREAM
                    )
                })
                message = "\n".join(addresses) if addresses else "No addresses returned"
            except OSError as error:
                message = f"Lookup failed: {error}"
            self.after(0, self.show_dns_results, hostname, message)
        threading.Thread(target=worker, daemon=True).start()
    def show_dns_results(self, hostname, message):
        self.dns_results.delete("1.0", "end")
        self.dns_results.insert(
            "end",
            f"DNS LOOKUP REPORT\n{'=' * 35}\n"
            f"Hostname: {hostname}\n\n"
            f"IP ADDRESSES\n{'-' * 35}\n"
            f"{message}\n\n"
            "This basic lookup does not retrieve MX or NS records.",
        )
    def check_ssl_certificate(self):
        hostname = self.ssl_entry.get().strip().rstrip(".")
        if (
            not hostname
            or "://" in hostname
            or "/" in hostname
            or "\\\\" in hostname
            or "@" in hostname
            or ":" in hostname
            or any(character.isspace() for character in hostname)
        ):
            self.ssl_results.delete("1.0", "end")
            self.ssl_results.insert(
                "end",
                "Enter a hostname only, such as example.com.\n"
                "Do not include https://, a path or a port.",
            )
            return
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            self.ssl_results.delete("1.0", "end")
            self.ssl_results.insert("end", "Invalid hostname")
            return
        self.ssl_results.delete("1.0", "end")
        self.ssl_results.insert(
            "end",
            f"Checking TLS certificate for {hostname}...\n",
        )
        self.ssl_check_button.configure(state="disabled")
        def worker():
            report = inspect_ssl_certificate(hostname)
            try:
                self.after(0, self.show_ssl_results, report)
            except RuntimeError:
                pass
        threading.Thread(target=worker, daemon=True).start()
    def show_ssl_results(self, report):
        self.ssl_results.delete("1.0", "end")
        self.ssl_results.insert("end", report)
        self.ssl_check_button.configure(state="normal")
    def check_security_headers(self):
        value = self.headers_entry.get().strip()
        self.headers_results.delete("1.0", "end")
        self.headers_results.insert(
            "end",
            "Checking HTTP security headers...\n",
        )
        self.headers_check_button.configure(state="disabled")
        def worker():
            try:
                report = inspect_security_headers(value)
                rendered = self.format_headers_report(report)
            except (ValueError, UnicodeError, RuntimeError) as error:
                rendered = f"HTTP headers check failed:\n{error}"
            except Exception as error:
                rendered = f"Unexpected error:\n{error}"
            try:
                self.after(0, self.show_headers_results, rendered)
            except RuntimeError:
                pass
        threading.Thread(target=worker, daemon=True).start()
    def format_headers_report(self, report):
        findings = report["findings"]
        applicable = [
            item for item in findings
            if item["status"] != "NOT APPLICABLE"
        ]
        present = sum(
            item["status"] == "PRESENT" for item in applicable
        )
        missing = sum(
            item["status"] == "MISSING" for item in applicable
        )
        lines = [
            "=" * 54,
            "HTTP SECURITY HEADERS REPORT",
            "=" * 54,
            f"Requested URL: {report['requested_url']}",
            f"Final URL:     {report['final_url']}",
            f"HTTP Status:   {report['status_code']}",
            "",
            f"Headers present: {present}/{len(applicable)}",
            f"Headers missing: {missing}",
            "",
            "HEADER FINDINGS",
            "-" * 54,
        ]
        for item in findings:
            lines.extend([
                "",
                f"[{item['status']}] {item['name']} ({item['severity']})",
                f"  {item['description']}",
            ])
            if item["value"]:
                lines.append(f"  Value: {item['value']}")
        lines.extend([
            "",
            "=" * 54,
            "NOTES",
            "-" * 54,
            "Missing headers are potential hardening opportunities,",
            "not automatic proof of a vulnerability",
            "Header values should be reviewed for correctness,",
            "not just presence",
            "=" * 54,
        ])
        return "\n".join(lines)
    def show_headers_results(self, report):
        self.headers_results.delete("1.0", "end")
        self.headers_results.insert("end", report)
        self.headers_check_button.configure(state="normal")
if __name__ == "__main__":
    app = NetSleuth()
    app.mainloop()
