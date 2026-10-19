import customtkinter as ctk
from urllib.parse import urlsplit
import ipaddress
import socket
import threading
from datetime import datetime


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

def inspect_url(value):
    value = value.strip()

    if not value:
        raise ValueError("Please Enter an URL") 

    if any(char.isspace() or ord(char) < 32 for char in value): 
        raise ValueError("URL cannot contain spaces or control characters")

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid URl:  {error} ") from error

    if parsed.scheme not in ("http",   "https") or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URl")

    hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()

    if len(hostname) > 235 or any(
        not part or len(part) > 63 for part in hostname.split(".")
    ):
        raise ValueError("Invalid Hostname")

    warnings = []  

    if parsed.scheme == "http":
        warnings.append("HTTP does not encrypt the connection")

    if "@" in parsed.netloc:
        warnings.append("@ in the URL can disguise the destination host")

    if len(value) > 200:
        warnings.append("Unusually long url") 

    
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
    """ Estimate risk using configured url """
    score = 0

    for warning in warnings:
        if "disguise the destination" in warning:
            score += 30
        elif "does not encrypt" in warning:
            score +=25
        elif "embedded credentials" in warning:
            score += 25
        elif "Ip address" in warning:
            score += 15
        elif "unusually long" in warning:
            score += 10
        elif "fragment " in warning:
            score += 5

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
    elif score >= 25:
        level = "Medium"
    else:
        level = "LOW"

    return score,level 

class NetSleuth(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetSleuth | URL Intelligence")
        self.geometry("850x650")
        self.minsize(700, 550)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.title_label = ctk.CTkLabel(
            self,
            text="NETSLEUTH",
            font=ctk.CTkFont(size=30, weight="bold"),
        )
        self.title_label.grid(
            row=0, column=0, padx=20, pady=(25, 5)
        )

        self.subtitle = ctk.CTkLabel(
            self,
            text="URL Inspection & DNS Intelligence",
            font=ctk.CTkFont(size=14),
            text_color="gray",
        )
        self.subtitle.grid(row=1, column=0, padx=20, pady=(0, 20))

        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(
            row=2, column=0, padx=25, pady=5, sticky="ew"
        )
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(
            self.input_frame,
            placeholder_text="Enter a URL, e.g. https://example.com",
            height=42,
        )
        self.url_entry.grid(
            row=0, column=0, padx=(12, 8), pady=12, sticky="ew"
        )
        self.url_entry.bind("<Return>", lambda event: self.analyze_url())

        self.analyze_button = ctk.CTkButton(
            self.input_frame,
            text="Analyze URL",
            height=42,
            command=self.analyze_url,
        )
        self.analyze_button.grid(
            row=0, column=1, padx=(0, 12), pady=12
        )

        self.results = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word",
        )
        self.results.grid(

            row=3, column=0, padx=25, pady=15, sticky="nsew"
        )

        self.status_label = ctk.CTkLabel(
            self,
            text="Ready — enter a URL to begin.",  
            anchor="w",
        )
        self.status_label.grid(
            row=4, column=0, padx=25, pady=(0, 15), sticky="ew"
        )

        self.show_welcome()

    def show_welcome(self):
        self.results.insert(
            "end",
            "Welcome to NetSleuth\n"
            "====================\n\n"
            "Inspect a URL to view its parsed components and warnings.\n"
            "You can also perform a DNS lookup for its hostname.\n\n"
            "Note: This tool performs basic static checks. "
            "A clean result does not prove a URL is safe.\n",
        ) 


    def write_results(self, text):
        self.results.delete("1.0", "end")
        self.results.insert("end", text)

    def analyze_url(self):
        value = self.url_entry.get()

        try:
            info = inspect_url(value)
        except (ValueError, UnicodeError) as error:
            self.status_label.configure(text="URL validation failed.")
            self.write_results(
                "URL INSPECTION FAILED\n"
                "=====================\n\n"
                f"Reason: {error}\n"
            )
            return

        report = [
            "URL INSPECTION REPORT",
            "=" * 45,
            f"Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"URL:    {info['url']}",
            "",
            "PARSED COMPONENTS",
            "-" * 45,
            f"Scheme: {info['scheme']}",
            f"Host:   {info['host']}",
            f"Port:   {info['port']}",
            f"Path:   {info['path']}",
            "",
            "WARNINGS",
            "-" * 45,
        ]

        if info["warnings"]:
            report.extend(
                f"[!] {warning}" for warning in info["warnings"]
            )
        else:
            report.append("No configured warnings were detected.")

        report.extend([
            "",
            "DNS LOOKUP",
            "-" * 45,
            "Looking up hostname...",
        ])

        self.write_results("\n".join(report))
        self.status_label.configure(text="URL inspected. Resolving DNS...")
        self.analyze_button.configure(state="disabled")

        worker = threading.Thread(
            target=self.resolve_dns,
            args=(info["host"],),
            daemon=True,
        )
        worker.start()

    def resolve_dns(self, hostname):
        try:
            results = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
            addresses = sorted({
                result[4][0] for result in results
            })

            if addresses:
                message = "\n".join(f"  {address}" for address in addresses)
            else:
                message = "  No addresses returned."

            status = "DNS lookup completed."
        except socket.gaierror as error:
            message = f"  DNS lookup failed: {error}"
            status = "DNS lookup failed."
        except OSError as error:
            message = f"  Network error: {error}"
            status = "DNS lookup encountered an error."

        self.after(0, self.finish_dns, message, status)

    def finish_dns(self, message, status):
        current = self.results.get("1.0", "end").rstrip()

        if "Looking up hostname..." in current:
            current = current.replace(
                "Looking up hostname...", message
            )
        else:
            current += "\n\nDNS LOOKUP\n" + message

        self.write_results(current)    
        self.status_label.configure(text=status)
        self.analyze_button.configure(state="normal")

if __name__ == "__main__":
    app = NetSleuth()
    app.mainloop()


