import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

from feature_utils import canonicalize_url, host_from_any, is_ip_literal

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

BASE_DIR = Path(__file__).resolve().parent
KAGGLE_DATASET_PATH = BASE_DIR / "malicious_phish.csv"
LOCAL_THREATS_PATH = BASE_DIR / "local_threats.csv"
OUTPUT_DATASET_PATH = BASE_DIR / "dataset_enriquecido.csv"
MANIFEST_PATH = BASE_DIR / "dataset_manifest.json"

# Decisión acordada: NO entrenar con IP-literals
KEEP_IP_LITERALS = False


def safe_get(url: str, timeout: int = 15) -> requests.Response:
    headers = {"User-Agent": "tfm-build-dataset/1.0"}
    response = requests.get(url, timeout=timeout, headers=headers)
    response.raise_for_status()
    return response


def is_valid_domain_url(url: str) -> bool:
    url = str(url).strip()
    if not url:
        return False

    host = host_from_any(url)
    if not host:
        return False

    if (not KEEP_IP_LITERALS) and is_ip_literal(host):
        return False

    return True


def filter_domain_urls(urls):
    kept = []
    for u in urls:
        u = str(u).strip()
        if is_valid_domain_url(u):
            kept.append(u)
    return kept


def fetch_urlhaus() -> pd.DataFrame:
    print("[*] Conectando con URLhaus (csv_recent)...")
    try:
        response = safe_get(URLHAUS_CSV_URL, timeout=20)
        lines = response.text.splitlines()

        data_lines = []
        for line in lines:
            if line.startswith("# id,dateadded"):
                data_lines.append(line.lstrip("# ").strip())
            elif not line.startswith("#"):
                data_lines.append(line)

        df = pd.read_csv(io.StringIO("\n".join(data_lines)), quotechar='"', skipinitialspace=True)

        if "url" not in df.columns:
            print("[!] URLhaus: no encuentro columna 'url'. Columnas:", list(df.columns))
            return pd.DataFrame()

        raw_urls = df["url"].dropna().astype(str).str.strip().tolist()
        filtered = filter_domain_urls(raw_urls)

        out = pd.DataFrame({"url": filtered, "type": "malware"})
        print(f"    -> URLhaus: {len(raw_urls)} crudo, {len(out)} tras filtrar IPs/hosts vacíos.")
        return out

    except Exception as e:
        print(f"[!] Error conectando con URLhaus: {e}")
        return pd.DataFrame()


def load_kaggle() -> pd.DataFrame:
    print(f"[*] Cargando dataset base ({KAGGLE_DATASET_PATH})...")

    if not KAGGLE_DATASET_PATH.exists():
        print(f"[!] No se encuentra {KAGGLE_DATASET_PATH}. Abortando.")
        return pd.DataFrame()

    df = pd.read_csv(KAGGLE_DATASET_PATH)

    if "url" not in df.columns or "type" not in df.columns:
        print("[!] Kaggle: columnas esperadas ('url','type') no encontradas.")
        print("    Columnas disponibles:", list(df.columns))
        return pd.DataFrame()

    df = df[["url", "type"]].copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    df = df[df["url"].apply(is_valid_domain_url)].copy()

    print(f"    -> Kaggle: {len(df)} registros tras filtrar IPs/hosts vacíos.")
    return df[["url", "type"]]


def load_local_threats() -> pd.DataFrame:
    if not LOCAL_THREATS_PATH.exists():
        print(f"[*] Inteligencia local ({LOCAL_THREATS_PATH}) no encontrada. Se omite.")
        return pd.DataFrame()

    print(f"[*] Cargando inteligencia local ({LOCAL_THREATS_PATH})...")
    try:
        df = pd.read_csv(LOCAL_THREATS_PATH)

        if "url" not in df.columns:
            print("[!] local_threats: falta columna 'url'. Se omite.")
            return pd.DataFrame()

        if "type" not in df.columns:
            df["type"] = "malware"

        df = df[["url", "type"]].copy()
        df["url"] = df["url"].astype(str).str.strip()
        df["type"] = df["type"].astype(str).str.strip().str.lower()

        df = df[df["url"].apply(is_valid_domain_url)].copy()

        print(f"    -> Local: {len(df)} registros tras filtrar IPs/hosts vacíos.")
        return df[["url", "type"]]

    except Exception as e:
        print(f"[!] Error leyendo {LOCAL_THREATS_PATH}: {e}")
        return pd.DataFrame()


def main():
    print("=== INICIANDO PIPELINE DE REENTRENAMIENTO (CTI) ===")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    kaggle_df = load_kaggle()
    if kaggle_df.empty:
        return

    urlhaus_df = fetch_urlhaus()
    local_df = load_local_threats()

    print("\n[*] Fusionando fuentes de inteligencia...")
    final_df = pd.concat([kaggle_df, urlhaus_df, local_df], ignore_index=True)

    final_df["url"] = final_df["url"].astype(str).str.strip()
    final_df["url_canon"] = final_df["url"].apply(canonicalize_url)

    # Eliminamos URLs que no se han podido canonicalizar
    before_invalid_drop = len(final_df)
    final_df = final_df[final_df["url_canon"].ne("")].copy()
    invalid_removed = before_invalid_drop - len(final_df)

    total_before_dedup = len(final_df)
    final_df.drop_duplicates(subset=["url_canon"], keep="last", inplace=True)
    duplicates_removed = total_before_dedup - len(final_df)

    print(f"    -> URLs inválidas eliminadas al canonicalizar: {invalid_removed}")
    print(f"    -> Duplicados eliminados (por url_canon): {duplicates_removed}")

    final_df[["url", "type"]].to_csv(OUTPUT_DATASET_PATH, index=False)
    print(f"\n[+] Dataset enriquecido guardado en: {OUTPUT_DATASET_PATH}")
    print(f"[+] Total final: {len(final_df)}")

    manifest = {
        "timestamp_utc": ts,
        "keep_ip_literals": KEEP_IP_LITERALS,
        "dedup_key": "url_canon",
        "sources": {
            "kaggle_path": str(KAGGLE_DATASET_PATH),
            "urlhaus_url": URLHAUS_CSV_URL,
            "local_threats_path": str(LOCAL_THREATS_PATH),
        },
        "counts": {
            "kaggle_after_filter": int(len(kaggle_df)),
            "urlhaus_after_filter": int(len(urlhaus_df)),
            "local_after_filter": int(len(local_df)),
            "total_before_dedup": int(total_before_dedup),
            "duplicates_removed": int(duplicates_removed),
            "final_total": int(len(final_df)),
        },
        "final_type_distribution": final_df["type"].value_counts().to_dict(),
        "output": str(OUTPUT_DATASET_PATH),
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"[+] Manifest guardado en: {MANIFEST_PATH}")
    print("===================================================")


if __name__ == "__main__":
    main()
