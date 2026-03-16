import os
import time
import json
import base64
import html
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse

import dns.resolver
import requests
from dotenv import load_dotenv
from opensearchpy import OpenSearch

load_dotenv()

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
STATE_INDEX = os.getenv("STATE_INDEX", "tfm-triaje-state")
HISTORY_INDEX = os.getenv("HISTORY_INDEX", "tfm-triaje-history")

TTL_CLEAN_DAYS = int(os.getenv("TTL_CLEAN_DAYS", "60"))
TTL_MALICIOUS_DAYS = int(os.getenv("TTL_MALICIOUS_DAYS", "7"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:35b-a3b-q8_0")
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "4096"))
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.0"))
WORKER_POLL_SECONDS = int(os.getenv("WORKER_POLL_SECONDS", "5"))

POLL_SECONDS = int(os.getenv("WORKER_POLL_SECONDS", "5"))

API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY", ""),
    "otx": os.getenv("OTX_API_KEY", ""),
    "urlscan": os.getenv("URLSCAN_API_KEY", ""),
    "google_safebrowsing": os.getenv("GSB_API_KEY", ""),
    "abuse_ch": os.getenv("ABUSECH_API_KEY", ""),
}

print("[*] Iniciando Worker LLM + OSINT...")

# Configuración de laboratorio / pruebas: conexión sin TLS ni verificación de certificados.
# No pensada como configuración de producción.
client = OpenSearch(hosts=[OPENSEARCH_URL], use_ssl=False, verify_certs=False)


def timed_step(name, fn, *args, **kwargs):
    print(f"    [>] {name}...")
    t0 = time.time()
    try:
        result = fn(*args, **kwargs)
        dt = time.time() - t0
        print(f"    [OK] {name} ({dt:.2f}s)")
        return result
    except Exception as e:
        dt = time.time() - t0
        print(f"    [!!] {name} FALLÓ ({dt:.2f}s): {e}")
        return {}


def append_history(doc: dict):
    try:
        client.index(index=HISTORY_INDEX, body=doc)
    except Exception as e:
        print(f"[DEBUG] Error escribiendo histórico en OS: {e}")


def get_host_from_target(target):
    target = str(target or "")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return (urlparse(target).hostname or "").lower()


def minimize_url_for_osint(raw_url: str, keep_path: bool = True, keep_query: bool = False) -> str:
    """
    Minimiza la URL enviada a OSINT externos.
    - Elimina fragment siempre
    - Elimina query por defecto
    - Conserva path si aporta valor analítico
    - Elimina credenciales embebidas del netloc
    """
    raw_url = html.unescape(str(raw_url or "").strip())

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    p = urlparse(raw_url)

    scheme = p.scheme or "https"
    host = (p.hostname or "").lower()
    if not host:
        return raw_url

    port = f":{p.port}" if p.port else ""
    netloc = f"{host}{port}"

    path = p.path if keep_path and p.path else "/"
    query = p.query if keep_query else ""

    return urlunparse((scheme, netloc, path, "", query, ""))


def safe_request(method, url, retries=2, backoff_factor=1.5, **kwargs):
    kwargs.setdefault("timeout", 8)
    for attempt in range(retries):
        try:
            response = requests.request(method.upper(), url, **kwargs)
            if response.status_code == 200:
                return response
            if 400 <= response.status_code < 500:
                return response
        except requests.exceptions.RequestException:
            pass

        if attempt < retries - 1:
            time.sleep(backoff_factor ** attempt)

    # En lugar de devolver None, forzamos un error de conexión
    raise ConnectionError(f"Fallo de conexión o timeout tras {retries} intentos: {url}")


def check_dns_blocklists(host):
    blocklists = {
        "Quad9": "149.112.112.112",
        "AdGuard": "94.140.14.14",
        "CleanBrowsing": "185.228.168.9",
    }

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = ["8.8.8.8"]
    res.timeout = 2
    res.lifetime = 3

    resolved_ips = []
    try:
        answers = res.resolve(host, "A")
        resolved_ips = [a.to_text() for a in answers]
    except Exception:
        return {
            "status": "unresolved_globally",
            "resolved_ips": [],
            "blocked_by": [],
            "is_dns_blocked": False,
        }

    blocked_by = []
    for name, server_ip in blocklists.items():
        res_test = dns.resolver.Resolver(configure=False)
        res_test.nameservers = [server_ip]
        res_test.timeout = 2
        res_test.lifetime = 3
        try:
            answers = res_test.resolve(host, "A")
            first_ip = answers[0].to_text()
            if first_ip in ("0.0.0.0", "127.0.0.1"):
                blocked_by.append(name)
        except dns.resolver.NXDOMAIN:
            blocked_by.append(name)
        except Exception:
            pass

    return {
        "status": "resolved",
        "resolved_ips": resolved_ips,
        "blocked_by": blocked_by,
        "is_dns_blocked": len(blocked_by) > 0,
    }


def get_rdap_domain_age(host):
    response = safe_request("GET", f"https://rdap.org/domain/{host}")
    if response and response.status_code == 200:
        data = response.json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                return {"registration_date": event.get("eventDate", "Unknown")}
    return {"registration_date": "Unknown"}


def get_virustotal_url(target_url):
    if not API_KEYS["virustotal"]:
        return {"checked": False, "found": False, "malicious": 0, "suspicious": 0}

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = safe_request("GET", url, headers={"x-apikey": API_KEYS["virustotal"]})

    if response and response.status_code == 200:
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"checked": True, "found": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    return {"checked": True, "found": False, "malicious": 0, "suspicious": 0}


def get_google_safebrowsing(target_url):
    if not API_KEYS["google_safebrowsing"]:
        return {"checked": False}

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEYS['google_safebrowsing']}"
    payload = {
        "client": {"clientId": "local-soc-script", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "MALICIOUS_BINARY"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}],
        },
    }
    response = safe_request("POST", url, json=payload)
    if response and response.status_code == 200:
        matches = response.json().get("matches", [])
        if matches:
            return {"checked": True, "listed": True, "threat_type": matches[0].get("threatType")}
    return {"checked": True, "listed": False}


def get_urlhaus_url(target_url):
    if not API_KEYS["abuse_ch"]:
        return {"checked": False, "listed": False}

    url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Auth-Key": API_KEYS["abuse_ch"]}
    response = safe_request("POST", url, headers=headers, data={"url": target_url})
    if response and response.status_code == 200:
        data = response.json()
        if data.get("query_status") == "ok":
            payloads = data.get("payloads", [])
            hashes = [p.get("response_sha256") for p in payloads if p.get("response_sha256")]
            return {"checked": True, "listed": True, "threat": data.get("tags", ["Unknown"]), "extracted_hashes": hashes}
    return {"checked": True, "listed": False}


def get_threatfox(host):
    if not API_KEYS["abuse_ch"]:
        return {"checked": False, "listed": False}

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": API_KEYS["abuse_ch"]}
    payload = {"query": "search_ioc", "search_term": host}
    response = safe_request("POST", url, headers=headers, json=payload)
    if response and response.status_code == 200:
        data = response.json()
        if data.get("query_status") == "ok":
            return {"checked": True, "listed": True}
    return {"checked": True, "listed": False}


def get_alienvault_otx(host):
    if not API_KEYS["otx"]:
        return {"checked": False, "pulse_count": 0}

    response = safe_request("GET", f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general", headers={"X-OTX-API-KEY": API_KEYS["otx"]})
    if response and response.status_code == 200:
        return {"checked": True, "pulse_count": response.json().get("pulse_info", {}).get("count", 0)}
    return {"checked": True, "pulse_count": 0}


def get_urlscan_search(host):
    if not API_KEYS["urlscan"]:
        return {"checked": False, "previous_scans": 0}

    response = safe_request("GET", f"https://urlscan.io/api/v1/search/?q=domain:{host}", headers={"API-Key": API_KEYS["urlscan"]})
    if response and response.status_code == 200 and response.json().get("results"):
        return {"checked": True, "previous_scans": len(response.json()["results"]), "latest_score": response.json()["results"][0].get("score", "N/A")}
    return {"checked": True, "previous_scans": 0}


def get_crt_sh(host):
    response = safe_request("GET", f"https://crt.sh/?q={host}&output=json")
    if response and response.status_code == 200:
        try:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                return {"checked": True, "has_tls_certificates": True, "cert_count": len(data)}
        except json.JSONDecodeError:
            pass
    return {"checked": True, "has_tls_certificates": False, "cert_count": 0}


def get_highest_priority_task():
    query = {
        "size": 1,
        "query": {"term": {"status": "PENDING"}},
        "sort": [{"llm_priority": {"order": "asc"}}, {"timestamp": {"order": "asc"}}],
    }
    try:
        response = client.search(index=STATE_INDEX, body=query)
        hits = response["hits"]["hits"]
        if hits:
            return hits[0]
    except Exception:
        pass
    return None


def claim_task(doc_id: str) -> bool:
    body = {
        "script": {
            "lang": "painless",
            "source": """
                if (ctx._source.status == 'PENDING') {
                    ctx._source.status = 'PROCESSING';
                    ctx._source.llm_timestamp = params.now;
                } else {
                    ctx.op = 'none';
                }
            """,
            "params": {"now": datetime.now(timezone.utc).isoformat()},
        }
    }
    try:
        resp = client.update(index=STATE_INDEX, id=doc_id, body=body)
        return resp.get("result") == "updated"
    except Exception:
        return False


def close_task(doc_id: str, source_data: dict, decision: str, expiration_iso: str, mitre_tags: str = ""):
    now_iso = datetime.now(timezone.utc).isoformat()
    body = {
        "script": {
            "lang": "painless",
            "source": """
                ctx._source.status = 'COMPLETED';
                ctx._source.current_decision = params.decision;
                ctx._source.decision_stage = 'FINAL';
                ctx._source.source = 'LLM';
                ctx._source.expiration = params.expiration;
                ctx._source.llm_timestamp = params.now;
                ctx._source.mitre_tags = params.mitre;
                if (ctx._source.containsKey('url_runtime')) {
                    ctx._source.remove('url_runtime');
                }
            """,
            "params": {"decision": decision, "expiration": expiration_iso, "now": now_iso, "mitre": mitre_tags},
        }
    }
    client.update(index=STATE_INDEX, id=doc_id, body=body)

    history_doc = {
        "timestamp": now_iso,
        "eventtime": int(source_data.get("eventtime", 0)),
        "hostname": source_data.get("hostname", ""),
        "service": source_data.get("service", ""),
        "cat": int(source_data.get("cat", 0)),
        "catdesc": source_data.get("catdesc", ""),
        "action": source_data.get("action", ""),
        "pipeline_stage": "L3_DECISION",
        "current_decision": decision,
        "decision_stage": "FINAL",
        "ml_prob_malicious": float(source_data.get("ml_prob_malicious", 0.0)),
        "llm_priority": int(source_data.get("llm_priority", 0)),
        "status": "COMPLETED",
        "source": "LLM",
        "expiration": expiration_iso,
        "mitre_tags": mitre_tags,
        "url_saneada": source_data.get("url_saneada", ""),
        "url_sha256": source_data.get("url_sha256", ""),
        "url_path": source_data.get("url_path", ""),
        "query_keys": source_data.get("query_keys", []),
        "ignored_reason": "",
    }
    append_history(history_doc)


def fail_task(doc_id: str):
    body = {
        "script": {
            "lang": "painless",
            "source": """
                ctx._source.status = 'FAILED';
                ctx._source.llm_timestamp = params.now;
            """,
            "params": {"now": datetime.now(timezone.utc).isoformat()},
        }
    }
    client.update(index=STATE_INDEX, id=doc_id, body=body)


def strip_code_fences(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()

def extract_first_json_object(text: str) -> dict:
    """
    Intenta extraer el primer objeto JSON válido desde una respuesta del modelo.
    Soporta:
    - JSON puro
    - JSON entre code fences
    - texto con basura antes/después del JSON
    """
    text = strip_code_fences(text)

    # 1) intento directo
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2) buscar primer objeto JSON balanceado
    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("No JSON object found", text, 0)

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape:
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                return json.loads(candidate)

    raise json.JSONDecodeError("No balanced JSON object found", text, start)


def run_osint_and_llm(target_url: str) -> dict:
    target_url_full = html.unescape(str(target_url or "").strip())
    if not target_url_full.startswith(("http://", "https://")):
        target_url_full = "https://" + target_url_full

    host = get_host_from_target(target_url_full)
    target_url_min = minimize_url_for_osint(target_url_full, keep_path=True, keep_query=False)

    print(f"    [*] Extracted Domain (Host-based OSINT): {host}")
    print(f"    [*] Sanitized URL (URL-based OSINT): {target_url_min}")
    print(f"    [*] Ollama model: {OLLAMA_MODEL}")

    t0_osint = time.time()

    telemetry = {
        "target_url": target_url_full,
        "domain": host,
        "domain_age_rdap": timed_step("RDAP", get_rdap_domain_age, host),
        "dns_intelligence": timed_step("DNS blocklists", check_dns_blocklists, host),
        "google_safebrowsing_url": timed_step("Google Safe Browsing", get_google_safebrowsing, target_url_min),
        "virustotal_url_scan": timed_step("VirusTotal", get_virustotal_url, target_url_min),
        "urlhaus_url_scan": timed_step("URLhaus", get_urlhaus_url, target_url_min),
        "threatfox_domain": timed_step("ThreatFox", get_threatfox, host),
        "alienvault_otx": timed_step("AlienVault OTX", get_alienvault_otx, host),
        "urlscan_history": timed_step("urlscan", get_urlscan_search, host),
        "crt_sh_tls": timed_step("crt.sh", get_crt_sh, host),
    }

    dt_osint = time.time() - t0_osint
    print(f"    [=] Tiempo total OSINT: {dt_osint:.2f} segundos")

    # Comprobar cuántas fuentes han fallado por error técnico (devuelven {})
    failed_sources = sum(1 for v in telemetry.values() if v == {})

    # Si fallan, por ejemplo, 4 o más fuentes (ajusta este número según prefieras)
    if failed_sources >= 4:
        print(f"    [!] ALERTA: {failed_sources} fuentes OSINT fallaron (posible corte de red). Abortando LLM.")
        return {"verdict": "ERROR_OSINT", "mitre": "Fallo de red en recolección OSINT", "raw_json": {}}

    json_data = json.dumps(telemetry, indent=2, ensure_ascii=False)

    prompt = f"""
You are a Senior Cyber Threat Intelligence (L3 CTI) Analyst. Evaluate this OSINT telemetry for the URL '{target_url}'.

STRICT RULES:
1. MALICIOUS TRIGGERS: If VirusTotal 'malicious' > 0, OR URLhaus 'listed' is true, OR Google Safe Browsing 'listed' is true, OR dns_intelligence 'is_dns_blocked' is true, the verdict MUST be MALICIOUS.
2. UNRATED MEANS CLEAN: If a domain has 0 malicious indicators across VT, URLhaus, Google, and DNS, the verdict MUST be CLEAN.
3. BENIGN IGNORANCE: A lack of historical data (e.g., 'Unknown' domain age) is completely normal for small businesses. DO NOT flag a domain as SUSPICIOUS just because it lacks history.
4. MITRE ATT&CK MAPPING: If the verdict is MALICIOUS or SUSPICIOUS, infer the most likely MITRE ATT&CK Tactics and Techniques. If CLEAN, leave the MITRE array empty.
5. IOC EXTRACTION: Extract any IPs from 'resolved_ips' and any hashes from 'extracted_hashes' into the extracted_iocs section.
6. OUTPUT: Respond ONLY with valid JSON.

JSON SCHEMA:
{{
  "target": "{target_url}",
  "verdict": "CLEAN",
  "confidence_score": 9,
  "threat_intel_summary": "2-sentence executive summary.",
  "key_indicators": ["List ALL specific data points and tools that returned hits"],
  "extracted_iocs": {{
    "ips": ["list of IPs if any"],
    "sha256_hashes": ["list of hashes if any"]
  }},
  "mitre_attack": [
    {{"id": "TXXXX", "tactic": "Tactic Name", "technique": "Technique Name"}}
  ]
}}

TELEMETRY:
{json_data}
""".strip()

    # --- NUEVO: Imprimir el prompt de forma visual ---
    print("\n" + "="*60)
    print("    [+] PROMPT ENVIADO AL LLM:")
    print("="*60)
    print(prompt)
    print("="*60 + "\n")

    print("    [*] Querying Ollama...")
    try:
        t0_llm = time.time()
        llm_response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "think": False,
                "options": {
                    "temperature": OLLAMA_TEMPERATURE,
                    "num_ctx": OLLAMA_NUM_CTX,
                },
            },
            timeout=300,
        )
        llm_response.raise_for_status()

        dt_llm = time.time() - t0_llm
        print(f"    [=] Tiempo total LLM: {dt_llm:.2f} segundos")

        ollama_payload = llm_response.json()

        # --- NUEVO: Leer 'response' y caer en 'thinking' si está vacío ---
        raw_response = (ollama_payload.get("response") or "").strip()
        thinking_response = (ollama_payload.get("thinking") or "").strip()

        if not raw_response and thinking_response:
            print("    [*] Nota: 'response' vacío, recuperando JSON desde 'thinking'...")
            raw_response = thinking_response

        print(f"    [*] Ollama done_reason: {ollama_payload.get('done_reason')}")
        print(f"    [*] Ollama response length: {len(raw_response)}")

        if not raw_response:
            print("    [!] Ollama devolvió 'response' y 'thinking' vacíos. Payload completo:")
            print(json.dumps(ollama_payload, indent=2, ensure_ascii=False)[:4000])
            return {"verdict": "SUSPICIOUS", "mitre": "Empty LLM response", "raw_json": {}}

        print("    [*] Raw LLM response (primeros 1000 chars):")
        print(repr(raw_response[:1000]))

        parsed_json = extract_first_json_object(raw_response)

        verdict = str(parsed_json.get("verdict", "SUSPICIOUS")).upper()

        mitre_list = parsed_json.get("mitre_attack", [])
        mitre_tags = ", ".join(
            f"{m.get('id', '')} - {m.get('technique', '')}"
            for m in mitre_list
            if isinstance(m, dict) and m.get("id")
        )

        return {
            "verdict": verdict,
            "mitre": mitre_tags,
            "raw_json": parsed_json,
        }

    except Exception as e:
        print(f"    [-] Error en el LLM: {e}")
        return {"verdict": "SUSPICIOUS", "mitre": "Error de Inferencia", "raw_json": {}}


def enviar_alerta(target_url, raw_llm_response):
    """
    Envía una alerta a un webhook externo en caso de que
    el LLM permita una tarea, para revisión de TI
    """
    webhook_url = "https://notify.sanjuandediosmalaga.es/alertas_urgentes"
    payload = {
        "text": f"🚨 ALERTA 🚨\nEl LLM ha evaluado la URL '{target_url}' y ha decidido que es PERMITIDO.\n\nRespuesta del LLM:\n{json.dumps(raw_llm_response, indent=2, ensure_ascii=False)}"
    }
    try:
        # Timeout corto para no colgar el script si el webhook falla
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print("    [!] Webhook de alerta urgente enviado correctamente.")
    except Exception as e:
        print(f"    [-] Error enviando webhook de alerta: {e}")


def main():
    while True:
        task = get_highest_priority_task()
        if not task:
            time.sleep(POLL_SECONDS)
            continue

        doc_id = task["_id"]
        if not claim_task(doc_id):
            time.sleep(1)
            continue

        try:
            current = client.get(index=STATE_INDEX, id=doc_id)
            source_data = current["_source"]
            raw_url = source_data.get("url_runtime", "")

            if not raw_url:
                print(f"[!] Tarea sin url_runtime; no se puede auditar por URL. Host: {source_data.get('hostname')}")
                fail_task(doc_id)
                time.sleep(1)
                continue

            target_url = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
            prioridad = source_data.get("llm_priority", 0)
            decision_ml = source_data.get("current_decision", "BLOQUEADO")

            print(f"\\n[+] TAREA RECIBIDA (Prioridad {prioridad}): {target_url}")

            llm_result = run_osint_and_llm(target_url)
            verdict = llm_result.get("verdict", "SUSPICIOUS").upper()

            now = datetime.now(timezone.utc)
            if verdict == "CLEAN":
                decision_final = "PERMITIDO"
                final_expiration = (now + timedelta(days=TTL_CLEAN_DAYS)).isoformat()
                print("    [!] El LLM ha permitido la URL. Disparando webhook de alerta...")
                enviar_alerta(target_url_min, llm_result.get("raw_json", {}))
            elif verdict in ("MALICIOUS", "SUSPICIOUS"):
                decision_final = "BLOQUEADO"
                final_expiration = (now + timedelta(days=TTL_MALICIOUS_DAYS)).isoformat()
            else:
                decision_final = "BLOQUEADO"
                final_expiration = (now + timedelta(days=1)).isoformat()

            if decision_ml != decision_final:
                print(f"    [!!!] EL LLM HA CORREGIDO AL ML -> Nuevo estado: {decision_final}")
            else:
                print(f"    [OK] El LLM confirma la decisión del ML -> {decision_final}")

            close_task(doc_id=doc_id, source_data=source_data, decision=decision_final, expiration_iso=final_expiration, mitre_tags=llm_result.get("mitre", ""))
            print("    -> Ticket cerrado. TTL final actualizado y URL cruda purgada.")

        except Exception as e:
            print(f"    [!] Error crítico procesando la tarea: {e}")
            try:
                # NUEVO: En lugar de usar fail_task, forzamos el cierre a BLOQUEADO
                print("    [!] Forzando estado a BLOQUEADO por seguridad (Fail-Closed).")
                now = datetime.now(timezone.utc)
                expiration = (now + timedelta(days=1)).isoformat()

                # Pasamos source_data si existe, si no, creamos un mock básico
                data_to_close = source_data if 'source_data' in locals() else {"url_saneada": "Error previo a lectura"}

                close_task(
                    doc_id=doc_id,
                    source_data=data_to_close,
                    decision="BLOQUEADO",
                    expiration_iso=expiration,
                    mitre_tags="System Exception"
                )
            except Exception as e2:
                print(f"    [!] Fallo catastrófico al intentar cerrar la tarea: {e2}")
                # Como último recurso absoluto, dejamos el estado original FAILED
                fail_task(doc_id)

        time.sleep(1)


if __name__ == "__main__":
    main()
