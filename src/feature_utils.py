import math
import hashlib
import ipaddress
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import pandas as pd
import tldextract

# ==========================================
# CONFIG / CONSTANTES
# ==========================================
# Keywords alineadas con el entrenamiento actual
KEYWORDS = ("login", "verify", "update", "secure", "bank", "account", "paypal")
FEATURE_COLUMNS = (
    "url_length",
    "host_length",
    "count_dots",
    "count_hyphens",
    "count_slashes",
    "count_digits",
    "count_subdomains",
    "has_ip",
    "has_keywords",
    "entropy",
)
IPV4_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
extractor = tldextract.TLDExtract(suffix_list_urls=None)

# Categorías "dudosas" FortiGuard que sí entran en el pipeline
DEFAULT_ALLOWED_CATEGORIES = {0, 90, 91}  # Unrated, Newly Observed Domain, Newly Registered Domain


# ==========================================
# HELPERS BÁSICOS
# ==========================================
def host_from_any(target: str, default_scheme: str = "https") -> str:
    """
    Extrae el hostname desde una URL completa o desde un host/path sin esquema.
    Devuelve siempre el host en minúsculas.
    `default_scheme` se usa solo si la entrada no trae esquema.
    """
    target = (target or "").strip()
    if not target:
        return ""

    if not target.startswith(("http://", "https://")):
        target = f"{default_scheme}://{target}"

    try:
        parsed = urlparse(target)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def canonicalize_url(url: str, default_scheme: str = "https") -> str:
    """
    Normaliza una URL para deduplicación:
    - añade esquema si falta
    - pone esquema y host en minúsculas
    - elimina fragmentos
    - elimina puertos por defecto
    - ordena parámetros de query
    - conserva path y query
    - nunca rompe ante URLs malformadas: devuelve "" si no puede canonicalizar
    """
    url = (url or "").strip()
    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = f"{default_scheme}://{url}"

    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    scheme = (parsed.scheme or default_scheme).lower()

    try:
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return ""

    if not hostname:
        return ""

    # parsed.port puede lanzar ValueError si el puerto está corrupto
    try:
        port = parsed.port
    except ValueError:
        port = None

    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parsed.path or "/"

    try:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query_pairs.sort()
        query = urlencode(query_pairs, doseq=True)
    except Exception:
        query = ""

    try:
        return urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return ""


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    lns = float(len(s))
    counts = [s.count(c) for c in set(s)]
    return -sum((c / lns) * math.log2(c / lns) for c in counts if c)


def build_runtime_url(service: str, raw_url: str) -> str:
    """
    FortiGate suele mandar `url` sin esquema.
    Para parseo/ML/OSINT, solo añadimos `https://` si el servicio es HTTPS.
    """
    raw_url = str(raw_url or "").strip()
    if not raw_url:
        return ""
    if raw_url.startswith(("http://", "https://")):
        return raw_url
    if str(service or "").upper() == "HTTPS":
        return "https://" + raw_url
    return raw_url


def extract_hostname_from_url(raw_url: str, service: str = "HTTPS") -> str:
    runtime = build_runtime_url(service, raw_url)
    parsed = urlparse(runtime)
    return (parsed.hostname or "").lower()


# ==========================================
# FEATURE ENGINEERING (alineado con train.py)
# ==========================================
def extract_features(url: str) -> pd.DataFrame:
    """
    Vector de 10 dimensiones alineado con train_fixed.py:
    - url_length
    - host_length
    - count_dots
    - count_hyphens
    - count_slashes
    - count_digits
    - count_subdomains
    - has_ip
    - has_keywords (conteo)
    - entropy
    """
    url = str(url or "")
    parsed = urlparse(url)
    netloc = parsed.netloc or ""
    ext = extractor(url)

    hostname_fallback = (ext.domain + "." + ext.suffix) if ext.suffix else ext.domain
    host = netloc if netloc else hostname_fallback

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_slashes": url.count("/"),
        "count_digits": sum(c.isdigit() for c in url),
        "count_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "has_ip": 1 if IPV4_RE.search(host or url) else 0,
        "has_keywords": sum(1 for kw in KEYWORDS if kw in url.lower()),
        "entropy": calculate_entropy(url),
    }
    return pd.DataFrame([[features[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)


# ==========================================
# SANEADO / PERSISTENCIA
# ==========================================
def sanitize_url_for_storage(raw_url: str, assume_service: str = "HTTPS") -> dict:
    """
    Persistencia anonimizada:
    - hostname
    - path
    - query_keys (solo nombres)
    - url_saneada = hostname + path + query_keys (sin valores)
    - url_sha256 = hash exacto de la URL original recibida (sin esquema si así llega)
    """
    raw_url = str(raw_url or "").strip()
    url_sha256 = hashlib.sha256(raw_url.encode("utf-8")).hexdigest()

    runtime = build_runtime_url(assume_service, raw_url)
    parsed = urlparse(runtime)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    query_keys = []
    seen = set()
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key not in seen:
            query_keys.append(key)
            seen.add(key)

    if query_keys:
        url_saneada = f"{hostname}{path}?{'&'.join(query_keys)}"
    else:
        url_saneada = f"{hostname}{path}"

    return {
        "hostname": hostname,
        "url_path": path,
        "query_keys": query_keys,
        "url_saneada": url_saneada,
        "url_sha256": url_sha256,
    }


# ==========================================
# FILTROS DE INGESTA
# ==========================================
def should_process_event(service: str, cat: int, allowed_categories=None) -> tuple[bool, str]:
    """
    Devuelve (procesar, motivo_si_no).
    Regla acordada:
      - service == HTTPS
      - cat in {0, 90, 91} por defecto
    """
    allowed_categories = allowed_categories or DEFAULT_ALLOWED_CATEGORIES

    service = str(service or "").upper()
    try:
        cat = int(cat)
    except Exception:
        return False, "invalid_cat"

    if service != "HTTPS":
        return False, "non_https_service"

    if cat not in allowed_categories:
        return False, "category_not_in_scope"

    return True, ""
