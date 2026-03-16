import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import joblib
import uvicorn
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from opensearchpy import OpenSearch

from feature_utils import (
    FEATURE_COLUMNS,
    build_runtime_url,
    extract_features,
    sanitize_url_for_storage,
    should_process_event,
)

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent

T_ALLOW = float(os.getenv("T_ALLOW", "0.92"))
T_BLOCK = float(os.getenv("T_BLOCK", "0.20"))

PROVISIONAL_ALLOW_TTL_MINUTES = int(os.getenv("PROVISIONAL_ALLOW_TTL_MINUTES", "15"))
PROVISIONAL_BLOCK_TTL_HOURS = int(os.getenv("PROVISIONAL_BLOCK_TTL_HOURS", "24"))
BLOCK_NONSTANDARD_HTTPS_PORTS = os.getenv("BLOCK_NONSTANDARD_HTTPS_PORTS", "0") == "1"

ALLOWED_CATEGORIES = {
    int(x.strip())
    for x in os.getenv("ALLOWED_CATEGORIES", "0,90,91").split(",")
    if x.strip()
}

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
STATE_INDEX = os.getenv("STATE_INDEX", "tfm-triaje-state")
HISTORY_INDEX = os.getenv("HISTORY_INDEX", "tfm-triaje-history")

MODEL_PATH = Path(os.getenv("MODEL_PATH", str(BASE_DIR / "ml_model.joblib")))

app = FastAPI(title="TFM Express - L1 ML + feeds dinámicos")


def enviar_alerta_urgente():
    """
    Envía una alerta urgente a un webhook externo en caso de que falle la carga del modelo
    """
    webhook_url = "https://notify.sanjuandediosmalaga.es/alertas_urgentes"
    payload = {
        "text": f"🚨 ALERTA MÁXIMA 🚨\nEl modelo no ha posido ser cargado"
    }
    try:
        # Timeout corto para no colgar el script si el webhook falla
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print("    [!] Webhook de alerta urgente enviado correctamente.")
    except Exception as e:
        print(f"    [-] Error enviando webhook de alerta: {e}")


def get_opensearch_client() -> OpenSearch:
    # Configuración de laboratorio / pruebas: conexión sin TLS ni verificación de certificados.
    # No pensada como configuración de producción.
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        use_ssl=False,
        verify_certs=False,
    )


os_client = get_opensearch_client()


def init_opensearch_indices():
    state_mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "eventtime": {"type": "long"},
                "hostname": {"type": "keyword"},
                "service": {"type": "keyword"},
                "cat": {"type": "integer"},
                "catdesc": {"type": "keyword"},
                "action": {"type": "keyword"},
                "current_decision": {"type": "keyword"},
                "decision_stage": {"type": "keyword"},
                "ml_prob_malicious": {"type": "float"},
                "llm_priority": {"type": "integer"},
                "status": {"type": "keyword"},
                "source": {"type": "keyword"},
                "expiration": {"type": "date"},
                "llm_timestamp": {"type": "date"},
                "mitre_tags": {"type": "keyword"},
                "url_saneada": {"type": "keyword"},
                "url_sha256": {"type": "keyword"},
                "url_path": {"type": "keyword"},
                "query_keys": {"type": "keyword"},
                "url_runtime": {"type": "keyword"},
                "first_seen": {"type": "date"},
                "last_seen": {"type": "date"},
                "event_count": {"type": "integer"},
                "ignored_reason": {"type": "keyword"},
            }
        }
    }

    history_mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "eventtime": {"type": "long"},
                "hostname": {"type": "keyword"},
                "service": {"type": "keyword"},
                "cat": {"type": "integer"},
                "catdesc": {"type": "keyword"},
                "action": {"type": "keyword"},
                "pipeline_stage": {"type": "keyword"},
                "current_decision": {"type": "keyword"},
                "decision_stage": {"type": "keyword"},
                "ml_prob_malicious": {"type": "float"},
                "llm_priority": {"type": "integer"},
                "status": {"type": "keyword"},
                "source": {"type": "keyword"},
                "expiration": {"type": "date"},
                "mitre_tags": {"type": "keyword"},
                "url_saneada": {"type": "keyword"},
                "url_sha256": {"type": "keyword"},
                "url_path": {"type": "keyword"},
                "query_keys": {"type": "keyword"},
                "ignored_reason": {"type": "keyword"},
            }
        }
    }

    try:
        if not os_client.indices.exists(index=STATE_INDEX):
            os_client.indices.create(index=STATE_INDEX, body=state_mapping)
            print(f"[+] Índice de estado '{STATE_INDEX}' creado.")
        if not os_client.indices.exists(index=HISTORY_INDEX):
            os_client.indices.create(index=HISTORY_INDEX, body=history_mapping)
            print(f"[+] Índice de histórico '{HISTORY_INDEX}' creado.")
    except Exception as e:
        print(f"[!] Error conectando/creando índices en OpenSearch: {e}")


def append_history(doc: dict):
    try:
        os_client.index(index=HISTORY_INDEX, body=doc)
    except Exception as e:
        print(f"[DEBUG] Error escribiendo histórico en OS: {e}")

def append_ignored_history(
    *,
    eventtime: int,
    action: str,
    service: str,
    cat: int,
    catdesc: str,
    hostname: str,
    raw_url_no_scheme: str,
    ignored_reason: str,
):
    now_iso = datetime.now(timezone.utc).isoformat()
    sanitized = sanitize_url_for_storage(raw_url_no_scheme, assume_service=service or "HTTPS")
    history_doc = {
        "timestamp": now_iso,
        "eventtime": int(eventtime) if eventtime is not None else 0,
        "hostname": hostname or sanitized["hostname"],
        "service": service,
        "cat": int(cat),
        "catdesc": catdesc,
        "action": action,
        "pipeline_stage": "IGNORED",
        "current_decision": "IGNORADO",
        "decision_stage": "FINAL",
        "ml_prob_malicious": 0.0,
        "llm_priority": 0,
        "status": "COMPLETED",
        "source": "FILTER",
        "expiration": now_iso,
        "mitre_tags": "",
        "url_saneada": sanitized["url_saneada"],
        "url_sha256": sanitized["url_sha256"],
        "url_path": sanitized["url_path"],
        "query_keys": sanitized["query_keys"],
        "ignored_reason": ignored_reason,
    }
    append_history(history_doc)


try:
    rf_model = joblib.load(MODEL_PATH)
    print(f"[+] Modelo ML '{MODEL_PATH}' cargado.")
except Exception as e:
    print(f"[!] ADVERTENCIA: No se pudo cargar {MODEL_PATH}. Error: {e}")
    rf_model = None


def get_state_doc(hostname: str):
    try:
        return os_client.get(index=STATE_INDEX, id=hostname)
    except Exception:
        return None


def get_cached_decision(hostname: str):
    doc = get_state_doc(hostname)
    if not doc or not doc.get("found"):
        return None

    src = doc["_source"]
    expiration = src.get("expiration")
    if not expiration:
        return None

    now = datetime.now(timezone.utc)
    try:
        exp = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    except Exception:
        return None

    if exp > now and src.get("current_decision") in ("PERMITIDO", "BLOQUEADO"):
        return src.get("current_decision")
    return None


def upsert_state_and_history(
    *,
    eventtime: int,
    action: str,
    service: str,
    cat: int,
    catdesc: str,
    hostname: str,
    raw_url_no_scheme: str,
    current_decision: str,
    decision_stage: str,
    ml_prob_malicious: float,
    llm_priority: int,
    status: str,
    source: str,
    expiration_iso: str,
    ignored_reason: str = "",
):
    now_iso = datetime.now(timezone.utc).isoformat()
    sanitized = sanitize_url_for_storage(raw_url_no_scheme, assume_service=service)

    state_doc = {
        "timestamp": now_iso,
        "eventtime": int(eventtime) if eventtime is not None else 0,
        "hostname": hostname,
        "service": service,
        "cat": int(cat),
        "catdesc": catdesc,
        "action": action,
        "current_decision": current_decision,
        "decision_stage": decision_stage,
        "ml_prob_malicious": float(ml_prob_malicious),
        "llm_priority": int(llm_priority),
        "status": status,
        "source": source,
        "expiration": expiration_iso,
        "llm_timestamp": None,
        "mitre_tags": "",
        "url_saneada": sanitized["url_saneada"],
        "url_sha256": sanitized["url_sha256"],
        "url_path": sanitized["url_path"],
        "query_keys": sanitized["query_keys"],
        "url_runtime": raw_url_no_scheme if status in ("PENDING", "PROCESSING") else None,
        "first_seen": now_iso,
        "last_seen": now_iso,
        "event_count": 1,
        "ignored_reason": ignored_reason,
    }

    script = {
        "source": """
            if (ctx._source.first_seen == null) { ctx._source.first_seen = params.now; }
            ctx._source.timestamp = params.doc.timestamp;
            ctx._source.eventtime = params.doc.eventtime;
            ctx._source.hostname = params.doc.hostname;
            ctx._source.service = params.doc.service;
            ctx._source.cat = params.doc.cat;
            ctx._source.catdesc = params.doc.catdesc;
            ctx._source.action = params.doc.action;
            ctx._source.current_decision = params.doc.current_decision;
            ctx._source.decision_stage = params.doc.decision_stage;
            ctx._source.ml_prob_malicious = params.doc.ml_prob_malicious;
            ctx._source.llm_priority = params.doc.llm_priority;
            ctx._source.status = params.doc.status;
            ctx._source.source = params.doc.source;
            ctx._source.expiration = params.doc.expiration;
            ctx._source.ignored_reason = params.doc.ignored_reason;
            ctx._source.url_saneada = params.doc.url_saneada;
            ctx._source.url_sha256 = params.doc.url_sha256;
            ctx._source.url_path = params.doc.url_path;
            ctx._source.query_keys = params.doc.query_keys;
            if (params.doc.url_runtime != null) {
                ctx._source.url_runtime = params.doc.url_runtime;
            }
            ctx._source.last_seen = params.now;
            if (ctx._source.event_count == null) {
                ctx._source.event_count = 1;
            } else {
                ctx._source.event_count += 1;
            }
        """,
        "lang": "painless",
        "params": {"doc": state_doc, "now": now_iso},
    }

    body = {
        "scripted_upsert": True,
        "script": script,
        "upsert": state_doc,
    }

    try:
        os_client.update(index=STATE_INDEX, id=hostname, body=body, retry_on_conflict=3)
    except Exception as e:
        print(f"[DEBUG] Error escribiendo estado en OS: {e}")

    history_doc = {
        "timestamp": now_iso,
        "eventtime": int(eventtime) if eventtime is not None else 0,
        "hostname": hostname,
        "service": service,
        "cat": int(cat),
        "catdesc": catdesc,
        "action": action,
        "pipeline_stage": "IGNORED" if ignored_reason else "L1_DECISION",
        "current_decision": current_decision,
        "decision_stage": decision_stage,
        "ml_prob_malicious": float(ml_prob_malicious),
        "llm_priority": int(llm_priority),
        "status": status,
        "source": source,
        "expiration": expiration_iso,
        "mitre_tags": "",
        "url_saneada": sanitized["url_saneada"],
        "url_sha256": sanitized["url_sha256"],
        "url_path": sanitized["url_path"],
        "query_keys": sanitized["query_keys"],
        "ignored_reason": ignored_reason,
    }
    append_history(history_doc)


@app.post("/api/v1/webhook")
async def fortigate_webhook(request: Request):
    try:
        payload = await request.json()

        eventtime = payload.get("eventtime", 0)
        action = str(payload.get("action", "")).strip().lower()
        service = str(payload.get("service", "")).strip().upper()
        cat = payload.get("cat", None)
        catdesc = str(payload.get("catdesc", "")).strip()
        raw_url_no_scheme = str(payload.get("url") or payload.get("requrl") or "").strip()
        payload_hostname = str(payload.get("hostname", "")).strip().lower()

        if not raw_url_no_scheme:
            raise HTTPException(status_code=400, detail="No URL provided")
        if cat is None:
            raise HTTPException(status_code=400, detail="No category provided")
        try:
            cat = int(cat)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid category")

        process, reason = should_process_event(service, cat, ALLOWED_CATEGORIES)
        if not process:
            sanitized = sanitize_url_for_storage(raw_url_no_scheme, assume_service=service or "HTTPS")
            append_ignored_history(
                eventtime=eventtime,
                action=action,
                service=service,
                cat=cat,
                catdesc=catdesc,
                hostname=sanitized["hostname"] or payload_hostname,
                raw_url_no_scheme=raw_url_no_scheme,
                ignored_reason=reason,
            )
            return {"action": "IGNORADO", "reason": reason}

        url_for_processing = build_runtime_url(service, raw_url_no_scheme)
        parsed = urlparse(url_for_processing)
        host = (parsed.hostname or payload_hostname or "").lower()

        if not host:
            raise HTTPException(status_code=400, detail="Unable to determine hostname")

        cached_decision = get_cached_decision(host)
        if cached_decision:
            print(f"--> [CACHE HIT] {host} ya evaluado. Veredicto: {cached_decision}")
            return {"action": cached_decision, "cached": True}

        if BLOCK_NONSTANDARD_HTTPS_PORTS and parsed.port and parsed.port != 443:
            expiration = (datetime.now(timezone.utc) + timedelta(hours=PROVISIONAL_BLOCK_TTL_HOURS)).isoformat()
            upsert_state_and_history(
                eventtime=eventtime,
                action=action,
                service=service,
                cat=cat,
                catdesc=catdesc,
                hostname=host,
                raw_url_no_scheme=raw_url_no_scheme,
                current_decision="BLOQUEADO",
                decision_stage="PROVISIONAL",
                ml_prob_malicious=1.0,
                llm_priority=3,
                status="PENDING",
                source="HEURISTIC",
                expiration_iso=expiration,
            )
            return {"action": "BLOQUEADO"}

        if not rf_model:
            enviar_alerta_urgente()
            return {"action": "BLOQUEADO", "reason": "model_not_loaded"}

        features_df = extract_features(url_for_processing)[list(FEATURE_COLUMNS)]
        probabilities = rf_model.predict_proba(features_df.to_numpy())[0]
        prob_benign, prob_malicious = float(probabilities[0]), float(probabilities[1])

        if prob_malicious >= T_BLOCK:
            decision = "BLOQUEADO"
            priority = 3
            expiration = (datetime.now(timezone.utc) + timedelta(hours=PROVISIONAL_BLOCK_TTL_HOURS)).isoformat()
        elif prob_benign >= T_ALLOW:
            decision = "PERMITIDO"
            priority = 1
            expiration = (datetime.now(timezone.utc) + timedelta(minutes=PROVISIONAL_ALLOW_TTL_MINUTES)).isoformat()
        else:
            decision = "BLOQUEADO"
            priority = 2
            expiration = (datetime.now(timezone.utc) + timedelta(hours=PROVISIONAL_BLOCK_TTL_HOURS)).isoformat()

        print(f"--> [ML] {host} | Riesgo: {prob_malicious:.2f} | Decisión: {decision} | Prioridad LLM: {priority}")

        upsert_state_and_history(
            eventtime=eventtime,
            action=action,
            service=service,
            cat=cat,
            catdesc=catdesc,
            hostname=host,
            raw_url_no_scheme=raw_url_no_scheme,
            current_decision=decision,
            decision_stage="PROVISIONAL",
            ml_prob_malicious=prob_malicious,
            llm_priority=priority,
            status="PENDING",
            source="ML",
            expiration_iso=expiration,
        )

        return {"action": decision}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] Error en webhook: {e}")
        return {"action": "BLOQUEADO", "reason": "internal_error"}


def get_list_from_os(decision_type: str) -> str:
    now_iso = datetime.now(timezone.utc).isoformat()
    query = {
        "_source": ["hostname"],
        "size": 10000,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"current_decision": decision_type}},
                    {"range": {"expiration": {"gt": now_iso}}},
                ]
            }
        }
    }

    domains = set()
    try:
        response = os_client.search(index=STATE_INDEX, body=query)
        for hit in response["hits"]["hits"]:
            host = hit["_source"]["hostname"]
            if host:
                domains.add(host)
                domains.add(f"*.{host}")
    except Exception as e:
        print(f"[DEBUG] Error generando lista {decision_type}: {e}")

    return ("\n".join(sorted(domains)) + "\n") if domains else ""


@app.get("/api/v1/trusted", response_class=PlainTextResponse)
async def get_trusted_list():
    return get_list_from_os("PERMITIDO")


@app.get("/api/v1/blocked", response_class=PlainTextResponse)
async def get_blocked_list():
    return get_list_from_os("BLOQUEADO")


@app.on_event("startup")
async def startup_event():
    init_opensearch_indices()


if __name__ == "__main__":
    print("[*] Iniciando servidor FastAPI en el puerto 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
