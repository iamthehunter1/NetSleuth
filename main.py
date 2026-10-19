
import customtkinter as ctk
from urllib.parse import urlsplit
import ipaddress
import socket
import threading
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

    if parsed.username or parsed.password:
        warnings.append("URL contains embedded credentials.")

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
        with socket.create_connection(
            (hostname, port), timeout=7
        ) as raw_socket:
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

        if san_lines:
            report.extend(san_lines)
        else:
            report.append("No SAN entries provided.")

        report.extend([
            "",
            "CERTIFICATE VERIFICATION",
            "-" * 54,
            "The certificate chain and hostname passed",
            "the system's configured TLS verification checks.",
            "",
            "Note: A valid certificate does not guarantee that",
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
            fg_color="#171521"
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(
            self.sidebar,
            text="◈ NetSleuth",
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color=PURPLE
        ).pack(padx=18, pady=(28, 4), anchor="w")

        ctk.CTkLabel(
            self.sidebar,
            text="SECURITY INTELLIGENCE",
            font=ctk.CTkFont(size=10),
            text_color=MUTED_COLOR
        ).pack(padx=20, pady=(0, 30), anchor="w")

        self.pages = {}

        self.content = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=BG_COLOR
        )
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(1, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkFrame(
            self.content,
            fg_color="transparent"
        )
        self.header.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=28,
            pady=(24, 10)
        )

        self.page_title = ctk.CTkLabel(
            self.header,
            text="URL Scanner",
            font=ctk.CTkFont(size=27, weight="bold"),
            text_color=TEXT_COLOR
        )
        self.page_title.pack(anchor="w")

        self.page_subtitle = ctk.CTkLabel(
            self.header,
            text="Inspect URLs, warnings and hostname information.",
            text_color=MUTED_COLOR
        )
        self.page_subtitle.pack(anchor="w", pady=(4, 0))

        self.page_area = ctk.CTkFrame(
            self.content,
            fg_color="transparent"
        )
        self.page_area.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=25,
            pady=(8, 20)
        )
        self.page_area.grid_rowconfigure(0, weight=1)
        self.page_area.grid_columnconfigure(0, weight=1)

        self.create_url_page()
        self.create_dns_page()
        self.create_ssl_page()

        self.nav_buttons = {}

        for name, label in [
            ("URL Scanner", "⌕   URL Scanner"),
            ("DNS Lookup", "◎   DNS Lookup"),
            ("SSL Checker", "SSL Checker"),
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
                command=lambda page=name: self.show_page(page)
            )
            button.pack(fill="x", padx=12, pady=4)
            self.nav_buttons[name] = button

        ctk.CTkLabel(
            self.sidebar,
            text="NETSLEUTH  •  LOCAL TOOL",
            text_color=MUTED_COLOR,
            font=ctk.CTkFont(size=10)
        ).pack(side="bottom", padx=14, pady=18)

        self.show_page("URL Scanner")

    def create_url_page(self):
        page = ctk.CTkFrame(
            self.page_area,
            fg_color="transparent"
        )
        self.pages["URL Scanner"] = page

        ctk.CTkLabel(
            page,
            text="Enter a URL to investigate",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(4, 10))

        self.url_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="https://example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR
        )
        self.url_entry.pack(fill="x", pady=(0, 10))
        self.url_entry.bind(
            "<Return>",
            lambda event: self.analyze_url()
        )

        ctk.CTkButton(
            page,
            text="Analyze URL",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.analyze_url
        ).pack(anchor="w", pady=(0, 16))

        self.results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148"
        )
        self.results.pack(fill="both", expand=True)

        self.results.insert(
            "end",
            "Welcome to NetSleuth\n\n"
            "Enter a URL to inspect its components and warnings.\n"
            "DNS address resolution runs after URL inspection.\n\n"
            "Risk indicators are heuristic checks, not proof "
            "that a website is malicious or safe.\n"
        )

    def create_dns_page(self):
        page = ctk.CTkFrame(
            self.page_area,
            fg_color="transparent"
        )
        self.pages["DNS Lookup"] = page

        ctk.CTkLabel(
            page,
            text="DNS Record Lookup",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(4, 6))

        ctk.CTkLabel(
            page,
            text="Look up A and AAAA addresses for a hostname.",
            text_color=MUTED_COLOR
        ).pack(anchor="w", pady=(0, 14))

        self.dns_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR
        )
        self.dns_entry.pack(fill="x", pady=(0, 10))
        self.dns_entry.bind(
            "<Return>",
            lambda event: self.lookup_dns()
        )

        ctk.CTkButton(
            page,
            text="Look Up Hostname",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.lookup_dns
        ).pack(anchor="w", pady=(0, 16))

        self.dns_results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148"
        )
        self.dns_results.pack(fill="both", expand=True)

        self.dns_results.insert(
            "end",
            "DNS lookup ready.\n\n"
            "Enter a hostname above to resolve its IP addresses."
        )

    def create_ssl_page(self):
        page = ctk.CTkFrame(
            self.page_area,
            fg_color="transparent"
        )
        self.pages["SSL Checker"] = page

        ctk.CTkLabel(
            page,
            text="SSL/TLS Certificate Checker",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(4, 6))

        ctk.CTkLabel(
            page,
            text="Inspect HTTPS certificates, expiry dates and TLS versions.",
            text_color=MUTED_COLOR
        ).pack(anchor="w", pady=(0, 14))

        self.ssl_entry = ctk.CTkEntry(
            page,
            height=43,
            placeholder_text="example.com",
            border_color=PURPLE,
            fg_color=PANEL_COLOR
        )
        self.ssl_entry.pack(fill="x", pady=(0, 10))
        self.ssl_entry.bind(
            "<Return>",
            lambda event: self.check_ssl_certificate()
        )

        self.ssl_check_button = ctk.CTkButton(
            page,
            text="Check Certificate",
            height=42,
            fg_color=PURPLE,
            hover_color=PURPLE_HOVER,
            command=self.check_ssl_certificate
        )
        self.ssl_check_button.pack(
            anchor="w",
            pady=(0, 16)
        )

        self.ssl_results = ctk.CTkTextbox(
            page,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=PANEL_COLOR,
            border_width=1,
            border_color="#393148"
        )
        self.ssl_results.pack(fill="both", expand=True)

        self.ssl_results.insert(
            "end",
            "SSL/TLS certificate checker ready.\n\n"
            "Enter a hostname such as example.com.\n\n"
            "The checker validates the certificate and hostname "
            "and displays certificate and TLS details.\n\n"
            "Internet access is required."
        )

    def check_ssl_certificate(self):
        hostname = self.ssl_entry.get().strip().rstrip(".")

        if (
            not hostname
            or "://" in hostname
            or "/" in hostname
            or "\\" in hostname
            or "@" in hostname
            or ":" in hostname
            or any(character.isspace() for character in hostname)
        ):
            self.ssl_results.delete("1.0", "end")
            self.ssl_results.insert(
                "end",
                "Enter a hostname only, such as example.com.\n"
                "Do not include https://, a path or a port."
            )
            return

        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            self.ssl_results.delete("1.0", "end")
            self.ssl_results.insert("end", "Invalid hostname.")
            return

        self.ssl_results.delete("1.0", "end")
        self.ssl_results.insert(
            "end",
            f"Checking TLS certificate for {hostname}...\nPlease wait."
        )

        self.ssl_check_button.configure(state="disabled")

        def worker():
            report = inspect_ssl_certificate(hostname)

            try:
                self.after(
                    0,
                    self.show_ssl_results,
                    report
                )
            except RuntimeError:
                pass

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def show_ssl_results(self, report):
        self.ssl_results.delete("1.0", "end")
        self.ssl_results.insert("end", report)
        self.ssl_check_button.configure(state="normal")

    def show_page(self, page_name):
        for page in self.pages.values():
            page.grid_forget()

        self.pages[page_name].grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        self.page_title.configure(text=page_name)

        subtitles = {
            "URL Scanner": "Inspect URLs, warnings and hostname information.",
            "DNS Lookup": "Resolve a hostname to its IP addresses.",
            "SSL Checker": "Inspect HTTPS certificates and TLS connections.",
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
            self.results.insert(
                "end",
                f"URL inspection failed:\n{error}"
            )
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
            report.append("No configured warnings detected.")

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
            daemon=True
        ).start()

    def resolve_dns(self, hostname):
        try:
            addresses = sorted({
                result[4][0]
                for result in socket.getaddrinfo(
                    hostname,
                    None,
                    type=socket.SOCK_STREAM
                )
            })

            message = (
                "\n".join(addresses)
                if addresses
                else "No addresses returned."
            )
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
                "end",
                "Enter a hostname such as example.com."
            )
            return

        self.dns_results.delete("1.0", "end")
        self.dns_results.insert("end", "Resolving hostname...")

        def worker():
            try:
                addresses = sorted({
                    result[4][0]
                    for result in socket.getaddrinfo(
                        hostname,
                        None,
                        type=socket.SOCK_STREAM
                    )
                })

                message = (
                    "\n".join(addresses)
                    if addresses
                    else "No addresses returned."
                )
            except OSError as error:
                message = f"Lookup failed: {error}"

            self.after(
                0,
                self.show_dns_results,
                hostname,
                message
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def show_dns_results(self, hostname, message):
        self.dns_results.delete("1.0", "end")
        self.dns_results.insert(
            "end",
            f"DNS LOOKUP REPORT\n{'=' * 35}\n"
            f"Hostname: {hostname}\n\n"
            f"IP ADDRESSES\n{'-' * 35}\n"
            f"{message}\n\n"
            "This basic lookup does not retrieve MX or NS records."
        )


if __name__ == "__main__":
    app = NetSleuth()
    app.mainloop()
