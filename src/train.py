import json
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    PrecisionRecallDisplay,
    average_precision_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from feature_utils import FEATURE_COLUMNS, extract_features

from pathlib import Path
from dotenv import load_dotenv


def to_jsonable(obj):
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if hasattr(obj, "item"):  # numpy scalars
        return obj.item()
    return obj


# ==========================
# CONFIG
# ==========================
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = Path(os.getenv("DATASET_PATH", str(BASE_DIR / "dataset_enriquecido.csv")))
MODEL_PATH = Path(os.getenv("MODEL_PATH", str(BASE_DIR / "ml_model.joblib")))
METRICS_PATH = Path(os.getenv("METRICS_PATH", str(BASE_DIR / "metrics.json")))
CM_PATH = Path(os.getenv("CM_PATH", str(BASE_DIR / "matriz_confusion_rf.png")))
PR_PATH = Path(os.getenv("PR_PATH", str(BASE_DIR / "pr_curve_rf.png")))

TEST_SIZE = float(os.getenv("TEST_SIZE", "0.20"))
RANDOM_STATE = int(os.getenv("RANDOM_STATE", "42"))
N_ESTIMATORS = int(os.getenv("N_ESTIMATORS", "200"))
N_JOBS = int(os.getenv("N_JOBS", "-1"))
POS_LABEL = 1 # Clase positiva: URL maliciosa

print("Cargando dataset...")
df = pd.read_csv(DATASET_PATH)

required_cols = {"url", "type"}
missing = required_cols - set(df.columns)
if missing:
    raise ValueError(f"Faltan columnas {missing} en {DATASET_PATH}. Columnas: {list(df.columns)}")

df["type"] = df["type"].astype(str).str.strip().str.lower()
df["is_malicious"] = df["type"].apply(lambda x: 0 if x == "benign" else 1)

df = df.dropna(subset=["url", "type"]).copy()
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"].ne("")].copy()

total = len(df)
mal = int(df["is_malicious"].sum())
ben = total - mal

print(f"Total de URLs: {total}. Maliciosas: {mal}, Benignas: {ben}")

print("Extrayendo características léxicas (puede tardar)...")
X = np.array([extract_features(u)[list(FEATURE_COLUMNS)].iloc[0].to_list() for u in df["url"]], dtype=float)
y = df["is_malicious"].values.astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y,
)

print("Entrenando Random Forest (balanced + OOB)...")
rf = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    class_weight="balanced",
    n_jobs=N_JOBS,
    random_state=RANDOM_STATE,
    oob_score=True,
    bootstrap=True,
)
rf.fit(X_train, y_train)

print("\n--- Evaluación del Modelo ---")
y_pred = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)
y_prob_mal = y_proba[:, POS_LABEL]

report_str = classification_report(y_test, y_pred, target_names=["Benign", "Malicious"])
report_dict = classification_report(y_test, y_pred, target_names=["Benign", "Malicious"], output_dict=True)

auprc = float(average_precision_score(y_test, y_prob_mal))
oob = float(getattr(rf, "oob_score_", float("nan")))

print(report_str)
print(f"AUPRC (Área bajo Precision-Recall): {auprc:.4f}")
print(f"OOB score (estimación interna tipo CV): {oob:.4f}")

print("\nGenerando gráficos de evaluación para anexos...")
labels = [0, 1]
cm = confusion_matrix(y_test, y_pred, labels=labels)

plt.figure(figsize=(7, 6))
plt.imshow(cm)
plt.title("Matriz de Confusión - Random Forest")
plt.xticks([0, 1], ["Benigno", "Malicioso"])
plt.yticks([0, 1], ["Benigno", "Malicioso"])
plt.xlabel("Predicción del Modelo")
plt.ylabel("Etiqueta Real")
for (i, j), v in np.ndenumerate(cm):
    plt.text(j, i, str(v), ha="center", va="center")
plt.tight_layout()
plt.savefig(CM_PATH, dpi=300)
plt.close()

plt.figure(figsize=(7, 6))
PrecisionRecallDisplay.from_predictions(
    y_test,
    y_prob_mal,
    pos_label=POS_LABEL,
    name="Random Forest L1",
)
plt.title("Curva Precision-Recall")
plt.tight_layout()
plt.savefig(PR_PATH, dpi=300)
plt.close()
print(f"Gráficos guardados: '{CM_PATH}' y '{PR_PATH}'")

print(f"\nGuardando modelo en {MODEL_PATH}...")
joblib.dump(rf, MODEL_PATH)

metrics = {
    "dataset_path": str(DATASET_PATH),
    "model_path": str(MODEL_PATH),
    "metrics_path": str(METRICS_PATH),
    "confusion_matrix_path": str(CM_PATH),
    "pr_curve_path": str(PR_PATH),
    "total_urls": int(total),
    "benign": int(ben),
    "malicious": int(mal),
    "test_size": float(TEST_SIZE),
    "random_state": int(RANDOM_STATE),
    "n_estimators": int(N_ESTIMATORS),
    "auprc": float(auprc),
    "oob_score": float(oob),
    "confusion_matrix_labels": labels,
    "confusion_matrix": cm.tolist(),
    "classification_report": report_dict,
}

with open(METRICS_PATH, "w", encoding="utf-8") as f:
    json.dump(to_jsonable(metrics), f, indent=2, ensure_ascii=False)

print(f"Métricas guardadas en {METRICS_PATH}")
print("¡Entrenamiento finalizado con éxito!")
