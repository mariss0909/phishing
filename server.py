import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from html import escape as escape_html
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("SENTINEL_DB_PATH", ROOT / "sentinel.sqlite3"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()
URLSCAN_SCAN_API = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_API = "https://urlscan.io/api/v1/result/"
URLSCAN_SCREENSHOT = "https://urlscan.io/screenshots/"
MAX_BODY_BYTES = 64 * 1024
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
MAX_PREVIEW_BYTES = 1024 * 1024
MAX_PREVIEW_CHARACTERS = 20000
KNOWN_DANGEROUS_DOMAINS = {
    domain.strip().casefold().rstrip(".")
    for domain in os.environ.get("SENTINEL_DANGEROUS_DOMAINS", "").split(",")
    if domain.strip()
}


class ApiError(Exception):
    def __init__(self, status, message, code="request_failed"):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


def database_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database_connection() as connection:
        connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('email', 'phone')),
                value TEXT NOT NULL,
                normalized_value TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                main_domain TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
                CREATE TABLE IF NOT EXISTS official_directory (
                    organization TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    emails_json TEXT NOT NULL,
                    phones_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    portal TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    main_domain TEXT NOT NULL DEFAULT '',
                    domains_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk TEXT NOT NULL CHECK (risk IN ('danger', 'warning', 'clear')),
                findings_json TEXT NOT NULL,
                hosts_json TEXT NOT NULL,
                sender TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )
        report_columns = {row["name"] for row in connection.execute("PRAGMA table_info(reports)")}
        if "sender" not in report_columns:
            connection.execute("ALTER TABLE reports ADD COLUMN sender TEXT NOT NULL DEFAULT ''")
        contact_columns = {row["name"] for row in connection.execute("PRAGMA table_info(contacts)")}
        if "main_domain" not in contact_columns:
            connection.execute("ALTER TABLE contacts ADD COLUMN main_domain TEXT NOT NULL DEFAULT ''")
        directory_columns = {row["name"] for row in connection.execute("PRAGMA table_info(official_directory)")}
        if "main_domain" not in directory_columns:
            connection.execute("ALTER TABLE official_directory ADD COLUMN main_domain TEXT NOT NULL DEFAULT ''")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_contact(contact_type, value):
    if contact_type == "email":
        return value.strip().casefold()
    return re.sub(r"\D", "", value)


def normalize_main_domain(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    clean = raw.replace("https://", "").replace("http://", "").replace("www.", "")
    clean = clean.split("/")[0].split("?")[0].split("#")[0].rstrip(".").lower()
    return clean


def validate_contact(payload):
    organization = str(payload.get("organization", "")).strip()
    contact_type = str(payload.get("type", "")).strip()
    value = str(payload.get("value", "")).strip()
    source = str(payload.get("source", "")).strip()
    main_domain = normalize_main_domain(payload.get("main_domain", "") or source)
    if not organization or len(organization) > 80:
        raise ApiError(400, "Organization name is required and must be at most 80 characters.")
    if contact_type not in {"email", "phone"}:
        raise ApiError(400, "Contact type must be email or phone.")
    if not value or len(value) > 120:
        raise ApiError(400, "Contact value is required and must be at most 120 characters.")
    if contact_type == "email" and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ApiError(400, "Enter a valid email address.")
    if contact_type == "phone" and len(normalize_contact(contact_type, value)) < 7:
        raise ApiError(400, "Enter a phone number with at least 7 digits.")
    parsed_source = urlsplit(source)
    if parsed_source.scheme != "https" or not parsed_source.hostname or parsed_source.username or parsed_source.password:
        raise ApiError(400, "Source must be an HTTPS URL without embedded credentials.")
    if not main_domain or "." not in main_domain:
        raise ApiError(400, "Main domain is required and should look like bank.com or bank.com.ph.")
    return {
        "organization": organization,
        "type": contact_type,
        "value": value,
        "normalized_value": normalize_contact(contact_type, value),
        "source": source,
        "main_domain": main_domain,
    }


def validate_scan_url(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ApiError(400, "Enter a URL up to 2,048 characters.", "invalid_url")
    value = value.strip()
    if any(character.isspace() for character in value):
        raise ApiError(400, "URL cannot contain whitespace.", "invalid_url")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise ApiError(400, "URL could not be parsed.", "invalid_url") from error
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ApiError(400, "Only complete HTTP or HTTPS links can be scanned.", "invalid_url")
    if parsed.username or parsed.password:
        raise ApiError(400, "Links containing embedded usernames or passwords are not accepted.", "invalid_url")
    hostname = hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith((".localhost", ".local", ".internal", ".home", ".lan")):
        raise ApiError(400, "Local or private-network hostnames cannot be submitted.", "private_host_blocked")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname or hostname.endswith((".test", ".example", ".invalid")):
            raise ApiError(400, "Use a public internet hostname.", "private_host_blocked")
        try:
            hostname.encode("idna")
        except UnicodeError as error:
            raise ApiError(400, "Hostname is invalid.", "invalid_url") from error
    else:
        if not address.is_global:
            raise ApiError(400, "Private, loopback, and reserved IP addresses cannot be submitted.", "private_host_blocked")
    clean_path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, clean_path, parsed.query, "")), hostname


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, resolved_ip, port, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self.resolved_ip = resolved_ip

    def connect(self):
        self.sock = socket.create_connection((self.resolved_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, resolved_ip, port, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.resolved_ip = resolved_ip

    def connect(self):
        raw_socket = socket.create_connection((self.resolved_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


class VisibleTextExtractor(HTMLParser):
    BLOCK_TAGS = {"article", "blockquote", "br", "dd", "div", "footer", "h1", "h2", "h3", "h4", "li", "main", "p", "section", "tr"}
    SKIP_TAGS = {"button", "form", "iframe", "noscript", "script", "style", "svg", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.text_parts = []
        self.title_depth = 0
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.title_depth += 1
        if tag in self.SKIP_TAGS:
            self.skip_depth += 1
        elif tag in self.BLOCK_TAGS and self.skip_depth == 0:
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag == "title" and self.title_depth:
            self.title_depth -= 1
        if tag in self.SKIP_TAGS and self.skip_depth:
            self.skip_depth -= 1
        elif tag in self.BLOCK_TAGS and self.skip_depth == 0:
            self.text_parts.append("\n")

    def handle_data(self, data):
        if self.title_depth:
            self.title_parts.append(data)
        elif self.skip_depth == 0:
            self.text_parts.append(data)


class SafePreviewMarkup(HTMLParser):
    ALLOWED_TAGS = {
        "a", "article", "blockquote", "br", "code", "dd", "div", "dl", "dt", "em", "footer",
        "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "li", "main", "ol", "p", "pre",
        "section", "small", "span", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
    }
    VOID_TAGS = {"br", "hr"}
    SKIP_TAGS = {
        "audio", "button", "canvas", "embed", "form", "head", "iframe", "input", "link", "math",
        "meta", "noscript", "object", "option", "script", "select", "style", "svg", "template",
        "textarea", "title", "video",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.open_tags = []
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if self.skip_depth:
            if tag in self.SKIP_TAGS:
                self.skip_depth += 1
            return
        if tag in self.SKIP_TAGS:
            self.skip_depth = 1
            return
        if tag == "img":
            alt = next((value for name, value in attrs if name == "alt" and value), "")
            if alt:
                self.parts.append(f"<span>[Image: {escape_html(alt, quote=False)}]</span>")
            return
        if tag not in self.ALLOWED_TAGS:
            return
        self.parts.append(f"<{tag}>")
        if tag not in self.VOID_TAGS:
            self.open_tags.append(tag)

    def handle_endtag(self, tag):
        if self.skip_depth:
            if tag in self.SKIP_TAGS:
                self.skip_depth -= 1
            return
        if tag not in self.open_tags:
            return
        while self.open_tags:
            open_tag = self.open_tags.pop()
            self.parts.append(f"</{open_tag}>")
            if open_tag == tag:
                break

    def handle_data(self, data):
        if not self.skip_depth:
            self.parts.append(escape_html(data, quote=False))

    def markup(self):
        while self.open_tags:
            self.parts.append(f"</{self.open_tags.pop()}>")
        return "".join(self.parts)


def resolve_public_addresses(hostname, port):
    if "%" in hostname:
        raise ApiError(400, "Scoped IP addresses are not allowed in previews.", "private_host_blocked")
    try:
        address = ipaddress.ip_address(hostname)
        addresses = [str(address)]
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
            records = socket.getaddrinfo(ascii_hostname, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(record[4][0] for record in records))
        except (UnicodeError, socket.gaierror, OSError) as error:
            raise ApiError(502, "Could not resolve the preview host.", "preview_host_unavailable") from error
    if not addresses or any(not ipaddress.ip_address(address.split("%", 1)[0]).is_global for address in addresses):
        raise ApiError(400, "The preview host resolves to a private or reserved network address.", "private_host_blocked")
    return addresses


def decode_preview_body(content_type, body):
    charset_match = re.search(r"charset\s*=\s*[\"']?([\w.-]+)", content_type, re.IGNORECASE)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def extract_preview_text(content_type, body):
    decoded = decode_preview_body(content_type, body)
    if "html" not in content_type.casefold() and "xhtml" not in content_type.casefold():
        return "", re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", decoded)[:MAX_PREVIEW_CHARACTERS]
    extractor = VisibleTextExtractor()
    try:
        extractor.feed(decoded)
        extractor.close()
    except Exception as error:
        raise ApiError(502, "The page markup could not be safely parsed as text.", "preview_parse_failed") from error
    title = re.sub(r"\s+", " ", " ".join(extractor.title_parts)).strip()[:200]
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in "".join(extractor.text_parts).splitlines()]
    visible_text = "\n".join(line for line in lines if line)
    visible_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", visible_text)
    return title, visible_text[:MAX_PREVIEW_CHARACTERS]


def extract_safe_preview_markup(content_type, body):
    decoded = decode_preview_body(content_type, body)
    if "html" not in content_type.casefold() and "xhtml" not in content_type.casefold():
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", decoded)[:MAX_PREVIEW_CHARACTERS]
        return f"<pre>{escape_html(text, quote=False)}</pre>"
    sanitizer = SafePreviewMarkup()
    try:
        sanitizer.feed(decoded)
        sanitizer.close()
    except Exception as error:
        raise ApiError(502, "The page markup could not be safely sanitized.", "preview_sanitize_failed") from error
    return sanitizer.markup()


def fetch_safe_preview(value):
    current_url, submitted_host = validate_scan_url(value)
    redirects = 0
    while True:
        parsed = urlsplit(current_url)
        default_port = 443 if parsed.scheme == "https" else 80
        try:
            port = parsed.port or default_port
        except ValueError as error:
            raise ApiError(400, "Preview URL has an invalid port.", "invalid_url") from error
        if port != default_port:
            raise ApiError(400, "Previews only allow standard HTTP and HTTPS ports.", "unsupported_port")
        addresses = resolve_public_addresses(parsed.hostname, port)
        host = parsed.hostname.encode("idna").decode("ascii")
        connection_type = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
        connection = connection_type(host, addresses[0], port, timeout=8)
        request_target = parsed.path or "/"
        if parsed.query:
            request_target += "?" + parsed.query
        try:
            connection.request(
                "GET",
                request_target,
                headers={
                    "Accept": "text/html,application/xhtml+xml,text/plain",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "User-Agent": "Sentinel-Safe-Preview/1.0",
                },
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location or redirects >= 3:
                    raise ApiError(502, "The page exceeded the safe redirect limit.", "preview_redirect_limit")
                current_url, _ = validate_scan_url(urljoin(current_url, location))
                redirects += 1
                continue
            if response.status != 200:
                raise ApiError(502, f"The page returned HTTP {response.status}.", "preview_http_error")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
                raise ApiError(415, "Only HTML and plain-text pages can be previewed; files are never downloaded.", "preview_content_type_blocked")
            content_length = response.getheader("Content-Length")
            if content_length and int(content_length) > MAX_PREVIEW_BYTES:
                raise ApiError(413, "The page is larger than the 1 MB preview limit.", "preview_too_large")
            body = response.read(MAX_PREVIEW_BYTES + 1)
            if len(body) > MAX_PREVIEW_BYTES:
                raise ApiError(413, "The page is larger than the 1 MB preview limit.", "preview_too_large")
            title, text = extract_preview_text(response.getheader("Content-Type", ""), body)
            safe_markup = extract_safe_preview_markup(response.getheader("Content-Type", ""), body)
            return {
                "status": "complete",
                "title": title,
                "text": text or "No readable text was found on this page.",
                "safeHtml": safe_markup,
                "submittedDomain": submitted_host,
                "finalDomain": (urlsplit(current_url).hostname or "").lower(),
                "httpStatus": response.status,
                "redirects": redirects,
                "contentType": content_type,
                "notice": "Fetched by the Sentinel server without browser cookies. Scripts, frames, and downloads were not run. The destination can see this computer/server's network address; this is not a remote sandbox.",
            }
        except (TimeoutError, OSError, http.client.HTTPException, ssl.SSLError) as error:
            raise ApiError(502, "Could not safely fetch this page. No preview was produced.", "preview_unavailable") from error
        finally:
            connection.close()


def expand_safe_link(value):
    value = str(value or "").strip()
    if value and "://" not in value:
        value = f"https://{value}"
    current_url, submitted_host = validate_scan_url(value)
    redirects = 0
    while True:
        parsed = urlsplit(current_url)
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        if port != default_port:
            raise ApiError(400, "Link expansion only allows standard HTTP and HTTPS ports.", "unsupported_port")
        addresses = resolve_public_addresses(parsed.hostname, port)
        host = parsed.hostname.encode("idna").decode("ascii")
        connection_type = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
        connection = connection_type(host, addresses[0], port, timeout=8)
        request_target = parsed.path or "/"
        if parsed.query:
            request_target += "?" + parsed.query
        try:
            connection.request(
                "GET",
                request_target,
                headers={
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Range": "bytes=0-0",
                    "User-Agent": "Sentinel-Link-Expander/1.0",
                },
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location or redirects >= 5:
                    raise ApiError(502, "The link exceeded the safe redirect limit.", "redirect_limit")
                current_url, _ = validate_scan_url(urljoin(current_url, location))
                redirects += 1
                continue
            final_host = (parsed.hostname or "").encode("idna").decode("ascii").casefold().rstrip(".")
            known_dangerous = any(
                final_host == domain or final_host.endswith(f".{domain}")
                for domain in KNOWN_DANGEROUS_DOMAINS
            )
            page_title = ""
            page_text = ""
            page_warning = ""
            try:
                page = fetch_safe_preview(current_url)
                page_title = page["title"]
                page_text = page["text"][:5000]
            except ApiError as error:
                page_warning = error.message
            return {
                "submittedDomain": submitted_host,
                "finalDomain": final_host,
                "redirects": redirects,
                "httpStatus": response.status,
                "knownDangerous": known_dangerous,
                "dangerousListConfigured": bool(KNOWN_DANGEROUS_DOMAINS),
                "pageTitle": page_title,
                "pageText": page_text,
                "pageWarning": page_warning,
            }
        except TimeoutError as error:
            raise ApiError(504, "The Sentinel server timed out connecting to this public host. Check outbound internet access or firewall settings; no destination was confirmed.", "expansion_timeout") from error
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            raise ApiError(502, "Could not safely resolve this link. No destination was confirmed.", "expansion_unavailable") from error
        finally:
            connection.close()


def urlscan_request(url, payload=None, timeout=20):
    if not URLSCAN_API_KEY:
        raise ApiError(503, "URL scanning is not configured. Set URLSCAN_API_KEY on the server.", "provider_not_configured")
    headers = {"API-Key": URLSCAN_API_KEY, "Accept": "application/json", "User-Agent": "Sentinel-Thesis/1.0"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.headers.get("Content-Type", ""), response.read(MAX_SCREENSHOT_BYTES + 1)
    except HTTPError as error:
        if error.code == 429:
            raise ApiError(429, "The scanning provider rate limit was reached. Try again later.", "provider_rate_limited") from error
        if error.code == 404:
            return 404, "application/json", b"{}"
        if error.code in {401, 403}:
            raise ApiError(502, "The scanning provider rejected the server API key.", "provider_auth_failed") from error
        raise ApiError(502, f"The scanning provider returned HTTP {error.code}.", "provider_error") from error
    except (TimeoutError, URLError, OSError) as error:
        raise ApiError(502, "Could not reach the scanning provider. No safety verdict was produced.", "provider_unavailable") from error


def summarize_urlscan_result(scan_id, data, submitted_host):
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    task = data.get("task") if isinstance(data.get("task"), dict) else {}
    verdicts = data.get("verdicts") if isinstance(data.get("verdicts"), dict) else {}
    urlscan_verdict = verdicts.get("urlscan") if isinstance(verdicts.get("urlscan"), dict) else {}
    overall_verdict = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    score = urlscan_verdict.get("score")
    categories = urlscan_verdict.get("categories") or []
    if isinstance(categories, str):
        categories = [categories]
    categories = [str(category)[:80] for category in categories[:10]]
    malicious = bool(overall_verdict.get("malicious") or urlscan_verdict.get("malicious"))
    try:
        numeric_score = int(score) if score is not None else None
    except (TypeError, ValueError):
        numeric_score = None
    if malicious or (numeric_score is not None and numeric_score >= 50) or any("phish" in category.casefold() or "malware" in category.casefold() for category in categories):
        risk = "danger"
    elif categories or (numeric_score is not None and numeric_score > 0):
        risk = "warning"
    elif numeric_score is not None:
        risk = "clear"
    else:
        risk = "warning"
    final_url = str(page.get("url", ""))
    try:
        final_host = (urlsplit(final_url).hostname or submitted_host).lower()
    except ValueError:
        final_host = submitted_host
    raw_domains = data.get("lists", {}).get("domains", []) if isinstance(data.get("lists"), dict) else []
    domains = list(dict.fromkeys([submitted_host, final_host, *(str(item).lower() for item in raw_domains if isinstance(item, str))]))[:20]
    title = str(page.get("title", ""))[:200]
    return {
        "scanId": scan_id,
        "status": "complete",
        "risk": risk,
        "riskLabel": {"danger": "Dangerous indicators found", "warning": "Review carefully", "clear": "No known threats found"}[risk],
        "notice": "This is one provider's result, not a guarantee. The scanned page was opened by urlscan.io, not on your device.",
        "submittedDomain": submitted_host,
        "finalDomain": final_host,
        "pageTitle": title,
        "httpStatus": str(page.get("status", ""))[:12],
        "redirected": bool(page.get("redirected")),
        "domains": domains,
        "score": numeric_score,
        "categories": categories,
        "provider": "urlscan.io private scan",
        "resultUrl": f"https://urlscan.io/result/{scan_id}/",
        "screenshotUrl": f"/api/scans/{scan_id}/screenshot",
        "createdAt": task.get("time", ""),
    }


def json_bytes(payload):
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


class SentinelHandler(BaseHTTPRequestHandler):
    server_version = "SentinelLocal/1.0"

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def send_json(self, status, payload):
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_api_error(self, error):
        self.send_json(error.status, {"error": error.code, "message": error.message})

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ApiError(400, "Invalid content length.") from error
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ApiError(413, "Request body must be between 1 byte and 64 KB.")
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ApiError(400, "Request body must be valid JSON.") from error
        if not isinstance(payload, dict):
            raise ApiError(400, "JSON request body must be an object.")
        return payload

    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            if path == "/api/health":
                self.send_json(200, {"status": "ok", "urlscanConfigured": bool(URLSCAN_API_KEY), "scanProvider": "urlscan.io", "scanVisibility": "private"})
                return
            if path == "/api/contacts":
                with database_connection() as connection:
                    rows = connection.execute("SELECT id, organization, type, value, source, main_domain, created_at FROM contacts ORDER BY organization COLLATE NOCASE").fetchall()
                self.send_json(200, {"contacts": [dict(row) for row in rows]})
                return
            if path == "/api/directory":
                with database_connection() as connection:
                    rows = connection.execute("SELECT organization, category, emails_json, phones_json, source, portal, note, main_domain, domains_json FROM official_directory ORDER BY organization COLLATE NOCASE").fetchall()
                entries = [{"organization": row["organization"], "category": row["category"], "emails": json.loads(row["emails_json"]), "phones": json.loads(row["phones_json"]), "source": row["source"], "portal": row["portal"], "note": row["note"], "mainDomain": row["main_domain"], "domains": json.loads(row["domains_json"])} for row in rows]
                self.send_json(200, {"entries": entries})
                return
            if path == "/api/reports":
                with database_connection() as connection:
                    rows = connection.execute("SELECT id, risk, findings_json, hosts_json, sender, created_at FROM reports ORDER BY id DESC LIMIT 100").fetchall()
                reports = [{"id": row["id"], "risk": row["risk"], "findings": json.loads(row["findings_json"]), "hosts": json.loads(row["hosts_json"]), "sender": row["sender"], "createdAt": row["created_at"]} for row in rows]
                self.send_json(200, {"reports": reports})
                return
            screenshot_match = re.fullmatch(r"/api/scans/([0-9a-f-]{36})/screenshot", path)
            if screenshot_match:
                self.handle_screenshot(screenshot_match.group(1))
                return
            scan_match = re.fullmatch(r"/api/scans/([0-9a-f-]{36})", path)
            if scan_match:
                self.handle_scan_result(scan_match.group(1))
                return
            if path == "/firebase-store.js":
                self.serve_firebase_store()
                return
            if path in {"/", "/index.html"}:
                self.serve_index()
                return
            raise ApiError(404, "Not found.", "not_found")
        except ApiError as error:
            self.send_api_error(error)
        except sqlite3.Error:
            self.send_json(500, {"error": "database_error", "message": "Database operation failed."})

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            payload = self.read_json()
            if path == "/api/contacts":
                self.create_contact(payload)
                return
            if path == "/api/reports":
                self.create_report(payload)
                return
            if path == "/api/scans":
                self.create_scan(payload)
                return
            if path == "/api/preview":
                self.create_preview(payload)
                return
            raise ApiError(404, "Not found.", "not_found")
        except ApiError as error:
            self.send_api_error(error)
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "duplicate_contact", "message": "That email or phone is already saved."})
        except sqlite3.Error:
            self.send_json(500, {"error": "database_error", "message": "Database operation failed."})

    def do_PUT(self):
        path = urlsplit(self.path).path
        if path == "/api/directory":
            try:
                entries = self.validate_directory_entries(self.read_json())
                updated_at = utc_now()
                with database_connection() as connection:
                    connection.execute("DELETE FROM official_directory")
                    connection.executemany(
                        "INSERT INTO official_directory (organization, category, emails_json, phones_json, source, portal, note, main_domain, domains_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [(entry["organization"], entry["category"], json.dumps(entry["emails"]), json.dumps(entry["phones"]), entry["source"], entry["portal"], entry["note"], entry["mainDomain"], json.dumps(entry["domains"]), updated_at) for entry in entries],
                    )
                self.send_json(200, {"entries": entries})
            except ApiError as error:
                self.send_api_error(error)
            except sqlite3.Error:
                self.send_json(500, {"error": "database_error", "message": "Database operation failed."})
            return
        match = re.fullmatch(r"/api/contacts/(\d+)", path)
        if not match:
            self.send_json(404, {"error": "not_found", "message": "Not found."})
            return
        contact_id = int(match.group(1))
        try:
            contact = validate_contact(self.read_json())
            with database_connection() as connection:
                cursor = connection.execute(
                    "UPDATE contacts SET organization = ?, type = ?, value = ?, normalized_value = ?, source = ?, main_domain = ? WHERE id = ?",
                    (contact["organization"], contact["type"], contact["value"], contact["normalized_value"], contact["source"], contact["main_domain"], contact_id),
                )
            if cursor.rowcount == 0:
                raise ApiError(404, "Contact not found.", "not_found")
            self.send_json(200, {"contact": {"id": contact_id, **{key: contact[key] for key in ("organization", "type", "value", "source", "main_domain")}}})
        except ApiError as error:
            self.send_api_error(error)
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "duplicate_contact", "message": "That email or phone is already saved."})
        except sqlite3.Error:
            self.send_json(500, {"error": "database_error", "message": "Database operation failed."})

    @staticmethod
    def validate_directory_entries(payload):
        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries or len(entries) > 500:
            raise ApiError(400, "Directory must contain between 1 and 500 entries.")
        validated = []
        organizations = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ApiError(400, "Each directory entry must be an object.")
            organization = str(entry.get("organization", "")).strip()
            category = str(entry.get("category", "")).strip()
            source = str(entry.get("source", "")).strip()
            portal = str(entry.get("portal", "")).strip()
            note = str(entry.get("note", "")).strip()
            main_domain = normalize_main_domain(entry.get("mainDomain", "") or source)
            emails = entry.get("emails", [])
            phones = entry.get("phones", [])
            domains = entry.get("domains", [])
            if not organization or len(organization) > 120 or organization.casefold() in organizations:
                raise ApiError(400, "Directory organizations must be unique and at most 120 characters.")
            organizations.add(organization.casefold())
            if not category or len(category) > 80 or len(note) > 2000:
                raise ApiError(400, "Directory category or note is invalid.")
            for value, label in ((source, "Source"), (portal, "Portal")):
                if value:
                    try:
                        parsed = urlsplit(value)
                        valid_url = parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                    except ValueError:
                        valid_url = False
                    if not valid_url or len(value) > 2048:
                        raise ApiError(400, f"{label} must be a valid HTTPS URL.")
            if not source:
                raise ApiError(400, "Every directory entry needs an HTTPS source URL.")
            if not main_domain or "." not in main_domain:
                raise ApiError(400, "Every directory entry needs a valid main domain.")
            if not isinstance(emails, list) or len(emails) > 50 or any(not isinstance(value, str) or len(value) > 254 for value in emails):
                raise ApiError(400, "Directory emails must contain up to 50 text values.")
            if not isinstance(phones, list) or len(phones) > 50 or any(not isinstance(value, str) or len(value) > 80 for value in phones):
                raise ApiError(400, "Directory phones must contain up to 50 text values.")
            if not isinstance(domains, list) or len(domains) > 100 or any(not isinstance(value, str) or len(value) > 253 for value in domains):
                raise ApiError(400, "Directory domains must contain up to 100 text values.")
            validated.append({"organization": organization, "category": category, "emails": emails, "phones": phones, "source": source, "portal": portal, "note": note, "mainDomain": main_domain, "domains": domains})
        return validated

    def do_DELETE(self):
        path = urlsplit(self.path).path
        match = re.fullmatch(r"/api/(contacts|reports)/(\d+)", path)
        if not match:
            self.send_json(404, {"error": "not_found", "message": "Not found."})
            return
        table, item_id = match.group(1), int(match.group(2))
        try:
            with database_connection() as connection:
                cursor = connection.execute(f"DELETE FROM {table} WHERE id = ?", (item_id,))
            if cursor.rowcount == 0:
                raise ApiError(404, "Item not found.", "not_found")
            self.send_json(200, {"deleted": True})
        except ApiError as error:
            self.send_api_error(error)
        except sqlite3.Error:
            self.send_json(500, {"error": "database_error", "message": "Database operation failed."})

    def create_contact(self, payload):
        contact = validate_contact(payload)
        with database_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO contacts (organization, type, value, normalized_value, source, main_domain, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (contact["organization"], contact["type"], contact["value"], contact["normalized_value"], contact["source"], contact["main_domain"], utc_now()),
            )
            contact_id = cursor.lastrowid
        self.send_json(201, {"contact": {"id": contact_id, **{key: contact[key] for key in ("organization", "type", "value", "source", "main_domain")}}})

    def create_report(self, payload):
        risk = payload.get("risk")
        findings = payload.get("findings", [])
        hosts = payload.get("hosts", [])
        sender = payload.get("sender", "")
        if risk not in {"danger", "warning", "clear"}:
            raise ApiError(400, "Risk must be danger, warning, or clear.")
        if not isinstance(sender, str) or len(sender) > 180:
            raise ApiError(400, "Sender must be text with at most 180 characters.")
        if not isinstance(findings, list) or len(findings) > 20 or any(not isinstance(item, str) or len(item) > 2000 for item in findings):
            raise ApiError(400, "Findings must contain up to 20 text items, each at most 2,000 characters.")
        if not isinstance(hosts, list) or len(hosts) > 20 or any(not isinstance(item, str) or len(item) > 253 for item in hosts):
            raise ApiError(400, "Hosts must be up to 20 hostnames.")
        created_at = utc_now()
        with database_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO reports (risk, findings_json, hosts_json, sender, created_at) VALUES (?, ?, ?, ?, ?)",
                (risk, json.dumps(findings), json.dumps(hosts), sender.strip(), created_at),
            )
            report_id = cursor.lastrowid
        self.send_json(201, {"report": {"id": report_id, "risk": risk, "findings": findings, "hosts": hosts, "sender": sender.strip(), "createdAt": created_at}})

    def create_scan(self, payload):
        if not URLSCAN_API_KEY:
            raise ApiError(503, "Remote scanning is unavailable until URLSCAN_API_KEY is configured on the server.", "provider_not_configured")
        if payload.get("consent") is not True:
            raise ApiError(400, "Explicit consent is required before submitting a link to urlscan.io.", "consent_required")
        submitted_url, host = validate_scan_url(payload.get("url"))
        status, _, response_body = urlscan_request(URLSCAN_SCAN_API, {"url": submitted_url, "visibility": "private"})
        if status not in {200, 201}:
            raise ApiError(502, "The scanning provider did not accept the submission.", "provider_error")
        try:
            response = json.loads(response_body)
            scan_id = str(uuid.UUID(response["uuid"]))
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise ApiError(502, "The scanning provider returned an invalid scan identifier.", "provider_error") from error
        created_at = utc_now()
        with database_connection() as connection:
            connection.execute("INSERT INTO scans (scan_id, host, status, created_at) VALUES (?, ?, 'pending', ?)", (scan_id, host, created_at))
        self.send_json(202, {"scanId": scan_id, "status": "pending", "submittedDomain": host, "visibility": "private", "message": "Submitted to urlscan.io. The page will open remotely, not in your browser."})

    def create_preview(self, payload):
        if payload.get("consent") is not True:
            raise ApiError(400, "Explicit consent is required before the server fetches a page preview.", "consent_required")
        self.send_json(200, fetch_safe_preview(payload.get("url")))

    def handle_scan_result(self, scan_id):
        try:
            scan_id = str(uuid.UUID(scan_id))
        except ValueError as error:
            raise ApiError(404, "Scan not found.", "not_found") from error
        with database_connection() as connection:
            row = connection.execute("SELECT host, status, result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            raise ApiError(404, "Scan not found.", "not_found")
        if row["status"] == "complete" and row["result_json"]:
            self.send_json(200, json.loads(row["result_json"]))
            return
        if not URLSCAN_API_KEY:
            raise ApiError(503, "Remote scanning is not configured.", "provider_not_configured")
        status, _, response_body = urlscan_request(f"{URLSCAN_RESULT_API}{scan_id}/")
        if status == 404:
            self.send_json(202, {"scanId": scan_id, "status": "pending", "message": "The remote scan is still running."})
            return
        try:
            provider_result = json.loads(response_body)
        except json.JSONDecodeError as error:
            raise ApiError(502, "The scanning provider returned invalid result data.", "provider_error") from error
        summary = summarize_urlscan_result(scan_id, provider_result, row["host"])
        with database_connection() as connection:
            connection.execute("UPDATE scans SET status = 'complete', result_json = ? WHERE scan_id = ?", (json.dumps(summary), scan_id))
        self.send_json(200, summary)

    def handle_screenshot(self, scan_id):
        try:
            scan_id = str(uuid.UUID(scan_id))
        except ValueError as error:
            raise ApiError(404, "Screenshot not found.", "not_found") from error
        with database_connection() as connection:
            exists = connection.execute("SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not exists:
            raise ApiError(404, "Screenshot not found.", "not_found")
        status, content_type, image = urlscan_request(f"{URLSCAN_SCREENSHOT}{scan_id}.png", timeout=30)
        if status != 200 or not content_type.startswith("image/") or len(image) > MAX_SCREENSHOT_BYTES:
            raise ApiError(502, "Screenshot is not available yet.", "screenshot_unavailable")
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Cache-Control", "private, max-age=300")
        self.send_header("Content-Length", str(len(image)))
        self.end_headers()
        self.wfile.write(image)

    def serve_index(self):
        content = (ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def serve_firebase_store(self):
        content = (ROOT / "firebase-store.js").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/javascript; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format_string, *args):
        message = format_string % args
        print(f"{self.log_date_time_string()} {self.client_address[0]} {message}")


def main():
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), SentinelHandler)
    print(f"Sentinel server running at http://{HOST}:{PORT}")
    print("URL scanning: " + ("configured (private urlscan.io submissions)" if URLSCAN_API_KEY else "not configured; set URLSCAN_API_KEY"))
    print("Local SQLite database: " + str(DATABASE_PATH))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()