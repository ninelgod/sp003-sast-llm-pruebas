import argparse, json, pathlib, sys, textwrap

sys.stdout.reconfigure(errors="replace")
ap = argparse.ArgumentParser()
ap.add_argument("prefijo"); ap.add_argument("archivo"); ap.add_argument("--run", type=int, default=1)
a = ap.parse_args()

R = pathlib.Path("results")
carpetas = sorted(d for d in R.iterdir() if d.is_dir() and d.name.startswith(a.prefijo + "_"))
if not carpetas:
    sys.exit(f"No hay carpeta results/{a.prefijo}_*  (revisa el prefijo con: dir results)")
d = carpetas[-1]

def leer(p):
    b = pathlib.Path(p).read_bytes()
    try: return b.decode("utf-8")
    except UnicodeDecodeError: return b.decode("cp1252")

filas = [json.loads(l) for l in leer(d / "transcripts.jsonl").splitlines() if l.strip()]
caso = next((r for r in filas if r["file"] == a.archivo and r["run"] == a.run), None)
if caso is None:
    sys.exit(f"No encontre {a.archivo} (corrida {a.run}) en {d.name}")

gt = json.load(open("ground_truth.json", encoding="utf-8"))[a.archivo]
real = f"Vulnerable, {gt['cwe']}, linea {gt['line']}" if gt["vulnerable"] else "Seguro (sin vulnerabilidad)"
linea = "=" * 78
corto = lambda s, n: (s if len(s) <= n else s[:n] + " ...")
w = lambda t, ind="  ": print(textwrap.fill(t, 100, initial_indent=ind, subsequent_indent=ind))

print(linea)
print(f"CONFIGURACION : {d.name}")
print(f"ARCHIVO       : {a.archivo}   |   Real: {real}   |   Corrida: {a.run}")
print("-" * 78)
if caso["tool_log"]:
    for i, t in enumerate(caso["tool_log"], 1):
        res = json.dumps(t["result"], ensure_ascii=False) if not isinstance(t["result"], str) else t["result"].replace("\n", " | ")
        print(f"[{i}] HERRAMIENTA: {t['tool']}   args={json.dumps(t['args'], ensure_ascii=False)}")
        w("Resultado: " + corto(res, 260))
    print("-" * 78)
elif a.prefijo != "sast":
    print("(sin llamadas a herramientas)"); print("-" * 78)
if a.prefijo != "sast":
    print("RESPUESTA DEL MODELO:")
    w(corto(caso["raw"].replace("\n", " "), 600))
    print("-" * 78)
print("HALLAZGOS REPORTADOS:" + ("  (ninguno)" if not caso["findings"] else ""))
for f in caso["findings"]:
    w(corto(json.dumps(f, ensure_ascii=False), 260))
print("-" * 78)
print(f"EVALUACION: TP={caso['tp']}  FP={caso['fp']}  FN={caso['fn']}  ALUCINACIONES={caso['hall']}  |  JSON valido: {caso['json_valido']}")
print(linea)