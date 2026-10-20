
import json
import os
import ipaddress
from pathlib import Path

import requests

IPINFO_API_URL = "https://ipinfo.io"
REQUEST_TIMEOUT = 10


def api_key_path():
    app_data = os.getenv("APPDATA")
    config_dir = Path(app_data) / "NetSleuth" if app_data else Path.home() / ".netsleuth"
    return config_dir / "api_keys.json"


def load_ipinfo_key():
    key_file = api_key_path()

    try:
        if not key_file.is_file():
            return ""

        with key_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data.get("ipinfo_token", "")

    except (OSError, json.JSONDecodeError, AttributeError):
        return ""


def save_ipinfo_key(api_key):
    api_key = api_key.strip()

    if not api_key:
        raise ValueError("API key cannot be empty")

    key_file = api_key_path()
    key_file.parent.mkdir(parents=True, exist_ok=True)

    with key_file.open("w", encoding="utf-8") as file:
        json.dump({"ipinfo_token": api_key}, file, indent=4)


def remove_ipinfo_key():
    key_file = api_key_path()

    try:
        if key_file.is_file():
            key_file.unlink()
            return True
        return False

    except OSError as error:
        raise OSError(f"Could not remove API key: {error}") from error


def validate_ipinfo_key(api_key):
    api_key = api_key.strip()

    if not api_key:
        return False, "API key cannot be empty"

    try:
        response = requests.get(
            f"{IPINFO_API_URL}/",
            params={"token": api_key},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code in (401, 403):
            return False, "Invalid API key or access denied"

        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict) or not data.get("ip"):
            return False, "Unexpected response from IPinfo"

        return True, "API key validated successfully"

    except requests.Timeout:
        return False, "Request timed out"

    except requests.ConnectionError:
        return False, "Could not connect to IPinfo"

    except requests.RequestException as error:
        return False, f"Request failed: {error}"

    except ValueError:
        return False, "Invalid response from IPinfo"


def lookup_ipinfo(api_key, ip_address=""):
    api_key = api_key.strip()
    ip_address = ip_address.strip()

    if not api_key:
        raise ValueError("Configure your IPinfo API key first")

    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as error:
            raise ValueError("Enter a valid IP address") from error

        endpoint = f"{IPINFO_API_URL}/{ip_address}"
    else:
        endpoint = f"{IPINFO_API_URL}/"

    try:
        response = requests.get(
            endpoint,
            params={"token": api_key},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            raise ValueError("Unexpected response from IPinfo")

        return data

    except requests.Timeout as error:
        raise RuntimeError("IPinfo request timed out") from error

    except requests.ConnectionError as error:
        raise RuntimeError("Could not connect to IPinfo") from error

    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else 0

        messages = {
            401: "Invalid IPinfo API key",
            403: "Access denied or API limit reached",
            429: "IPinfo rate limit reached"
        }

        message = messages.get(status, f"IPinfo returned HTTP {status}")
        raise RuntimeError(message) from error

    except requests.RequestException as error:
        raise RuntimeError(f"IPinfo request failed: {error}") from error

    except ValueError as error:
        raise ValueError("Invalid response from IPinfo") from error
