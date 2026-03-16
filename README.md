# README

# Detección y curación de URLs dudosas en entornos FortiGate mediante una arquitectura híbrida ML+LLM local

## Descripción

Este repositorio contiene el código y la documentación de un Trabajo Fin de Máster orientado a automatizar el tratamiento de URLs dudosas en entornos FortiGate mediante una arquitectura híbrida compuesta por:

- un plano **L1 de triaje rápido** basado en Machine Learning (Random Forest),
- un plano **L3 cognitivo y asíncrono** basado en un LLM local vía Ollama,
- una capa de persistencia dual en OpenSearch,
- y una realimentación automática al firewall mediante **Remote Categories** (`IA_TRUSTED` / `IA_BLOCKED`).

La solución está diseñada para actuar sobre eventos de categorías web dudosas, concretamente:

- `Unrated`
- `Newly Observed Domain`
- `Newly Registered Domain`

El objetivo no es decidir en línea sobre la primera petición, sino **curar la memoria perimetral para accesos posteriores**, manteniendo una política **fail-close** en el perímetro.

El sistema está orientado a **reducir bloqueos** repetidos sobre dominios legítimos no categorizados y a **consolidar decisiones** locales sobre dominios dudosos antes de que los motores de reputación externos los absorban.

---

## Arquitectura resumida

- **L1 (**`app.py`**)**: recibe el webhook, filtra el evento, evalúa el caso y publica los feeds.
- **L3 (**`worker_llm.py`**)**: procesa casos pendientes, consulta OSINT y consolida el veredicto.
- **Persistencia**: OpenSearch mantiene estado operativo e histórico saneado.
- **Integración perimetral**: FortiGate consume `/api/v1/trusted` y `/api/v1/blocked` como feeds dinámicos.

---

## Modelo de despliegue

El sistema se despliega de forma mayoritariamente contenedorizada:

- **Docker Compose** levanta:
    - `OpenSearch`
    - `OpenSearch Dashboards`
    - `app`
    - `worker`
- **Ollama** permanece como servicio externo del host

Esta decisión simplifica la reproducibilidad del despliegue y mantiene el motor LLM desacoplado del stack principal.

> **Nota de entorno**  
> El despliegue mostrado en este repositorio está planteado como **entorno de laboratorio / pruebas** para facilitar la reproducibilidad del TFM. En particular, `docker-compose.yml` desactiva la capa de seguridad de OpenSearch y los clientes Python se conectan sin TLS ni verificación de certificados. **No debe interpretarse como una configuración de producción**.

---

## Alcance operativo

La implementación final está acotada de forma deliberada a:

- `service = HTTPS`
- `cat = 0` → `Unrated`
- `cat = 90` → `Newly Observed Domain`
- `cat = 91` → `Newly Registered Domain`

Quedan fuera del flujo automático:

- HTTP
- otras categorías de Web Filter
- URL Shortening
- enforcement por ruta o URL completa

---

## Estructura del repositorio

```text
.
├── README.md
├── LICENSE
├── .gitignore
├── .dockerignore
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── src/
│   ├── app.py
│   ├── worker_llm.py
│   ├── feature_utils.py
│   ├── build_dataset.py
│   └── train.py
├── docs/
│   ├── memoria.md
│   └── diagrama_flujo.png
└── artifacts/
    ├── metrics.json
    ├── dataset_manifest.json  
    ├── matriz_confusion_rf.png
    └── pr_curve_rf.png
```

## Componentes principales

### `src/app.py`

Servicio L1 que:

- recibe el webhook de FortiGate,
- filtra eventos fuera de scope,
- consulta caché en OpenSearch,
- ejecuta el modelo ML si procede,
- escribe estado e histórico,
- y expone los feeds `/api/v1/trusted` y `/api/v1/blocked`.

### `src/worker_llm.py`

Worker L3 que:

- consume tareas `PENDING`,
- recopila telemetría OSINT,
- consulta al LLM local,
- corrige o confirma la decisión L1,
- actualiza `tfm-triaje-state`,
- registra el cierre en `tfm-triaje-history`,
- y elimina la URL cruda temporal.

### `src/feature_utils.py`

Utilidades compartidas para:

- extracción de features,
- normalización y canonización de URL,
- saneamiento para persistencia,
- y lógica de scope.

### `src/build_dataset.py`

Construcción del dataset enriquecido a partir de:

- fuente base histórica,
- campañas recientes (URLhaus),
- inteligencia local opcional.

### `src/train.py`

Entrenamiento y evaluación del modelo L1:

- `RandomForestClassifier`
- split estratificado
- `oob_score=True`
- generación de métricas y gráficos

---

## Requisitos

### Host

- Docker
- Docker Compose
- Ollama instalado y operativo en el host
- modelo LLM descargado en Ollama

### Servicios

- OpenSearch
- OpenSearch Dashboards
- FortiGate con Web Filter y Automation Stitch

### Librerías Python

Incluidas en `requirements.txt` para la construcción de la imagen.

---

## Configuración

### 1\. Copiar el fichero de entorno

```
cp .env.example .env
```

### 2\. Ajustar variables principales

Lo mínimo imprescindible es completar los tokens de las fuentes OSINT consultadas:

```
# Claves API OSINT
VT_API_KEY=
OTX_API_KEY=
URLSCAN_API_KEY=
GSB_API_KEY=
ABUSECH_API_KEY=
```

### 3\. Descargar el modelo en Ollama

Ejemplo:

```
ollama pull qwen3.5:35b-a3b-q8_0
```

### 4\. Configurar Ollama para aceptar conexiones desde Docker

Como `app` y `worker` se ejecutan en contenedores y Ollama permanece en el host, Ollama no debe escuchar únicamente en `127.0.0.1`.

En Linux con systemd, puede configurarse mediante:

```
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

Después:

```
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

Verificación recomendada:

```
ss -ltnp | grep 11434
```

Y desde el contenedor:

```
docker compose exec worker curl http://host.docker.internal:11434/api/tags
```

---

## Arranque del stack

El fichero `docker-compose.yml` levanta los servicios principales del sistema:

- `opensearch`
- `opensearch-dashboards`
- `app`
- `worker`

El servicio `Ollama` no forma parte del stack y debe estar operativo en el host o en otro nodo accesible por red.

El arranque principal del sistema se realiza con:

```
docker compose up -d --build
```

---

## Verificación

### Ver servicios

```
docker compose ps
```

### Ver logs del plano L1

```
docker compose logs -f app
```

### Ver logs del plano L3

```
docker compose logs -f worker
```

### Ver OpenSearch

```
curl http://localhost:9200
```

### Ver feeds

```
curl http://localhost:8000/api/v1/trusted
curl http://localhost:8000/api/v1/blocked
```

---

## Integración con FortiGate

### Flujo operativo

- FortiGate bloquea la primera petición por Web Filter.
- Automation Stitch envía un webhook a `app`.
- L1 procesa el evento.
- L3 audita asíncronamente si procede.
- `app` materializa feeds dinámicos.
- FortiGate refresca `IA_TRUSTED` / `IA_BLOCKED`.

### Remote Categories

La integración se apoya en dos recursos externos tipo categoría:

- `IA_TRUSTED`
- `IA_BLOCKED`

Consumidos por FortiGate con `refresh-rate=1`.

### Unidad de enforcement

La implementación exporta siempre:

- `hostname`
- `*.hostname`

No se implementa enforcement por URL completa en esta versión.

La inferencia se realiza sobre URL completa por su mayor riqueza léxica, pero la materialización en FortiGate se aplica por FQDN exacto y wildcard; esta pérdida de granularidad se asume de forma deliberada en esta versión por simplicidad operativa, compatibilidad con Remote Categories y robustez de enforcement.

---

## Entrenamiento del modelo

### 1\. Construcción del dataset

```
python src/build_dataset.py
```

### Fuente del dataset de entrenamiento

El pipeline parte de un dataset base procedente de **Malicious URLs Dataset (**`malicious_phish.csv`**)**, publicado por **sid321axn** en Kaggle y compilado a partir de fuentes como **ISCX-URL-2016** y **PhishTank**. Sobre esta base, `build_dataset.py` incorpora además campañas recientes obtenidas desde **URLhaus** para construir `dataset_enriquecido.csv`, que es el conjunto finalmente utilizado en el entrenamiento del modelo L1.

> El repositorio no incluye el fichero bruto `malicious_phish.csv`; el pipeline de construcción del dataset parte de fuentes externas y/o locales que deben mantenerse fuera del control de versiones. La licencia y condiciones de uso del dataset original deben revisarse en su fuente de publicación correspondiente.

### 2\. Entrenamiento

```
python src/train.py
```

### Salidas esperadas

- `src/dataset_enriquecido.csv`
- `src/dataset_manifest.json`
- `src/ml_model.joblib`
- `src/metrics.json`
- `src/matriz_confusion_rf.png`
- `src/pr_curve_rf.png`

Nota: en el repositorio se presentan la mayoría ya generados en `artifacts/`

### Política de artefactos del repositorio

Los artefactos generados por el pipeline son regenerables. En el repositorio se prioriza la inclusión de artefactos ligeros y útiles para la revisión académica, como `dataset_manifest.json`, `metrics.json` y las figuras de evaluación. Otros artefactos de mayor tamaño, como `dataset_enriquecido.csv` o el modelo entrenado `ml_model.joblib`, pueden omitirse del repositorio público sin afectar a la reproducibilidad del flujo, ya que su generación queda documentada por los scripts del proyecto. En particular, `ml_model.joblib` no se incluye por defecto debido a su tamaño, mientras que los resultados del entrenamiento quedan reflejados en los artefactos de evaluación y metadatos asociados.

### Importante

Si se reentrena el modelo L1, es necesario reconstruir la imagen para que el nuevo `ml_model.joblib` quede incorporado al contenedor:

```
docker compose up -d --build
```

---

## Explicación del score L1

La clase positiva del clasificador L1 se corresponde con la categoría URL maliciosa. En consecuencia, la salida principal del modelo se interpreta como `p_mal`, esto es, la probabilidad estimada de que la URL analizada pertenezca a la clase maliciosa.

A partir de esta magnitud se definen dos umbrales operativos:

- si `p_mal ≥ T_BLOCK`, se activa una decisión conservadora de bloqueo inicial,
- si `1 - p_mal ≥ T_ALLOW`, se admite una decisión provisional de permiso,
- y en la zona intermedia el clasificador no se interpreta como criterio autónomo de decisión final, sino como mecanismo de priorización y escalado hacia el plano L3.

---

## Seguridad y privacidad

- El LLM se ejecuta localmente.
- La URL cruda solo se conserva temporalmente durante el procesamiento.
- El estado persistido se limita a campos saneados y artefactos operativos.

Este repositorio no incluye credenciales reales, `.env` operativo, telemetría sensible ni direcciones internas de producción.

---

## Limitaciones conocidas

- La arquitectura es asíncrona: la primera petición siempre se bloquea.
- La curación depende del refresco del feed por FortiGate.
- El sistema solo cubre HTTPS y las categorías 0, 90 y 91.
- El enforcement por hostname no resuelve por sí mismo todos los casos de hosting compartido.
- El LLM puede equivocarse; el diseño mitiga su impacto con prompting restrictivo, TTL y trazabilidad.
- La rapidez del plano L1 se refiere al tiempo de inferencia, no al tiempo de aplicación efectiva en el firewall, que depende del refresco del feed.

---

## Resultados y evaluación

El modelo L1 se evaluó mediante split estratificado 80/20, AUPRC y estimación OOB. En la revisión actual, el entrenamiento reporta `AUPRC = 0.9633` y `OOB score = 0.9356`.

El detalle de la evaluación experimental y funcional forma parte de la memoria del TFM y de sus anexos.

---

## Documentación adicional

Este repositorio actúa como soporte técnico del TFM. La memoria académica, los anexos y el material gráfico asociado pueden incluirse en `docs/` para ampliar la justificación, la evaluación y el contexto del proyecto.

---

## Licencia

El código de este repositorio se distribuye bajo licencia Apache-2.0. Véase el fichero `LICENSE` para el texto completo.

---

## Autor

Sergio Alonso Berrido  
Trabajo Fin de Máster - Máster en IA Aplicada a la Ciberseguridad