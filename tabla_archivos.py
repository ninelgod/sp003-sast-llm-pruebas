import argparse, csv, json, pathlib

ap = argparse.ArgumentParser()
ap.add_argument("--a", default="qwen2.5-7b"); ap.add_argument("--b", default="llama3.1-8b")
a = ap.parse_args()
R = pathlib.Path("results")

def leer(ruta):
    """runner.py en Windows guarda en cp1252; se intenta UTF-8 y luego cp1252."""
    datos = pathlib.Path(ruta).read_bytes()
    try:
        return datos.decode("utf-8")
    except UnicodeDecodeError:
        return datos.decode("cp1252")

def ultima(prefijo):
    c = sorted(d for d in R.iterdir() if d.is_dir() and d.name.startswith(prefijo + "_"))
    return c[-1] if c else None

configs = [("SAST", "sast"), ("A · LLM", f"llm_{a.a}"), ("A · Híbrido", f"hybrid_{a.a}"), ("B · LLM", f"llm_{a.b}"), ("B · Híbrido", f"hybrid_{a.b}")]
datos = {}
for nombre, pref in configs:
    d = ultima(pref)
    if d is None:
        print(f"AVISO: no hay carpeta results/{pref}_*  ->  columna '{nombre}' quedara vacia"); datos[nombre] = {}; continue
    filas = [json.loads(l) for l in leer(d / "transcripts.jsonl").splitlines() if l.strip()]
    datos[nombre] = {r["file"]: r for r in filas if r["run"] == 1}

def etiqueta(r):
    partes = [n for n, k in (("TP", "tp"), ("FP", "fp"), ("FN", "fn")) if r[k]]
    if not partes: partes = ["TN"]
    if r["hall"]: partes.append("ALUC")
    t = "+".join(partes)
    return t + ("*" if not r["json_valido"] else "")

gt = json.load(open("ground_truth.json", encoding="utf-8"))
cabecera = ["Archivo", "Real"] + [c[0] for c in configs]
filas_out = []
for f in sorted(gt):
    fila = [f, "Vuln." if gt[f]["vulnerable"] else "Seguro"]
    for nombre, _ in configs:
        r = datos[nombre].get(f)
        fila.append(etiqueta(r) if r else "")
    filas_out.append(fila)

anchos = [max(len(str(x[i])) for x in [cabecera] + filas_out) for i in range(len(cabecera))]
for fila in [cabecera] + filas_out:
    print("  ".join(str(c).ljust(w) for c, w in zip(fila, anchos)))
print("\nLeyenda: TP acierto | FP falso positivo | FN falso negativo | TN seguro sin hallazgos | ALUC alucinacion | * respuesta sin JSON valido (p. ej. rechazo del modelo)")
with open(R / "tabla_por_archivo.csv", "w", newline="", encoding="utf-8-sig") as fh:
    w = csv.writer(fh); w.writerow(cabecera); w.writerows(filas_out)
print("Guardado: results/tabla_por_archivo.csv")