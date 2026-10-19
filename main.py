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