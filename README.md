# SP-003 · Pruebas de LLM + Tool Calling para análisis SAST

## 1. Qué mide
Compara 3 condiciones sobre 14 archivos Python (7 vulnerables, 7 seguros) con verdad de referencia en `ground_truth.json`:

| Modo | Qué es |
|---|---|
| `sast` | Solo Semgrep con reglas locales (`rules.yml`). Línea base, sin LLM. |
| `llm` | El LLM recibe el código y responde sin herramientas. |
| `hybrid` | El LLM usa Tool Calling (`run_semgrep`, `read_file`) y hace el triaje. |

Los casos incluyen dos trampas a propósito: `13_sqli_percent.py` (vulnerable, pero Semgrep no la detecta) y `14_system_constant.py` (segura, pero Semgrep la marca).

Métricas: precisión, recall, F1, FPR sobre archivos seguros, tasa de alucinación (hallazgo con línea fuera de rango, CWE inválido o evidencia que no existe en el archivo), consistencia entre corridas, JSON inválido, latencia y llamadas a herramientas.

## 2. Preparación
```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
semgrep --version
export ANTHROPIC_API_KEY=...        # Windows PowerShell: $env:ANTHROPIC_API_KEY="..."
```
Semgrep corre nativo en Linux/macOS. En Windows usa WSL o Docker (`docker run --rm -v "${PWD}:/src" semgrep/semgrep ...`).
Para un modelo de pesos abiertos local: instala Ollama, descarga un modelo con soporte de herramientas (`ollama pull qwen2.5:7b`) y usa `--provider openai --base-url http://localhost:11434/v1`.

## 3. Ejecución (en este orden)
```bash
python runner.py --mode sast
python runner.py --mode llm    --provider anthropic --model <MODELO_A> --runs 3
python runner.py --mode hybrid --provider anthropic --model <MODELO_A> --runs 3
python runner.py --mode llm    --provider openai --base-url http://localhost:11434/v1 --model qwen2.5:7b --runs 3
python runner.py --mode hybrid --provider openai --base-url http://localhost:11434/v1 --model qwen2.5:7b --runs 3
```
Cada ejecución crea `results/<modo>_<modelo>_<fecha>/` con `transcripts.jsonl` (respuesta cruda, hallazgos y llamadas a herramientas por archivo) y `metrics.json`, y agrega una fila a `results/summary.csv`.

## 4. Evidencia a entregar
1. Capturas de la terminal de cada ejecución (con fecha/hora y las métricas finales).
2. La carpeta `results/` completa (transcripts, metrics y summary.csv).
3. Captura de `semgrep --version` y de los modelos usados (nombre exacto y versión).
4. El repositorio con este código (commit con fecha).
5. Tabla comparativa final (copiada de `summary.csv`) y 3 ejemplos concretos de transcripts: un acierto, un falso positivo y una alucinación.
6. Una sección "Resultados y análisis" en el informe, con los números reales obtenidos.

## 5. Límites que debes declarar en el informe
- Muestra pequeña (14 archivos): los resultados son indicativos, no estadísticamente concluyentes.
- Los casos son sintéticos y de un solo lenguaje; lo recomendable es ampliar con muestras pareadas de PrimeVul.
- Temperatura 0 reduce, pero no elimina, la variabilidad; por eso se repite 3 veces.
- Nunca incluyas tus API keys en el repositorio ni en las capturas.
