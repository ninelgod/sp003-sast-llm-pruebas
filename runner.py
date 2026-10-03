#!/usr/bin/env python3
import argparse, csv, json, pathlib, re, subprocess, time, datetime

ROOT = pathlib.Path(__file__).parent
CASES = ROOT / "cases"
GT = json.load(open(ROOT / "ground_truth.json"))
CWE_RE = re.compile(r"^CWE-\d+$")

SYSTEM = ("Eres un auditor de seguridad de codigo (SAST). Analiza el archivo y reporta SOLO vulnerabilidades reales. "
          "Si el codigo es seguro, devuelve una lista vacia. Responde unicamente con JSON valido con la forma: "
          '{"findings":[{"line":<int>,"cwe":"CWE-<n>","evidence":"<linea exacta de codigo>","explanation":"<breve>"}]}')

def read_numbered(name):
    lines = (CASES / name).read_text().splitlines()
    return "\n".join(f"{i}: {l}" for i, l in enumerate(lines, 1))

# ---------- herramientas ----------
def tool_run_semgrep(path):
    p = subprocess.run(["semgrep", "--config", str(ROOT / "rules.yml"), "--json", "--quiet", "--metrics=off", str(CASES / pathlib.Path(path).name)],
                       capture_output=True, text=True)
    src = (CASES / pathlib.Path(path).name).read_text().splitlines()
    out = []
    for r in json.loads(p.stdout or "{}").get("results", []):
        ln = r["start"]["line"]
        out.append({"line": ln, "cwe": r["extra"]["metadata"]["cwe"], "rule": r["check_id"].split(".")[-1], "code": src[ln - 1].strip()})
    return out

def tool_read_file(path):
    f = CASES / pathlib.Path(path).name
    return read_numbered(f.name) if f.exists() else "ERROR: archivo no existe"

HANDLERS = {"run_semgrep": tool_run_semgrep, "read_file": tool_read_file}
TOOL_SPECS = [
    {"name": "run_semgrep", "description": "Ejecuta el escaner SAST Semgrep sobre un archivo y devuelve los hallazgos candidatos (linea, CWE, regla, codigo). Puede tener falsos positivos y falsos negativos.",
     "schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "read_file", "description": "Lee un archivo del proyecto y devuelve su contenido con numeros de linea.",
     "schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
]

# ---------- proveedores ----------
class Anthropic:
    def __init__(self, model):
        import anthropic; self.c = anthropic.Anthropic(); self.model = model
    def chat(self, user, tools=False, max_iter=6):
        msgs = [{"role": "user", "content": user}]; log = []
        spec = [{"name": t["name"], "description": t["description"], "input_schema": t["schema"]} for t in TOOL_SPECS] if tools else []
        for _ in range(max_iter):
            kw = {"tools": spec} if spec else {}
            r = self.c.messages.create(model=self.model, max_tokens=1500, temperature=0, system=SYSTEM, messages=msgs, **kw)
            msgs.append({"role": "assistant", "content": r.content})
            if r.stop_reason != "tool_use":
                return "".join(b.text for b in r.content if b.type == "text"), log
            results = []
            for b in r.content:
                if b.type == "tool_use":
                    out = HANDLERS[b.name](**b.input); log.append({"tool": b.name, "args": b.input, "result": out})
                    results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(out, ensure_ascii=False)})
            msgs.append({"role": "user", "content": results})
        return "", log

class OpenAICompat:
    def __init__(self, model, base_url=None):
        import openai; self.c = openai.OpenAI(base_url=base_url, api_key=__import__("os").environ.get("OPENAI_API_KEY", "ollama")); self.model = model
    def chat(self, user, tools=False, max_iter=6):
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]; log = []
        spec = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["schema"]}} for t in TOOL_SPECS] if tools else None
        for _ in range(max_iter):
            kw = {"tools": spec} if spec else {}
            m = self.c.chat.completions.create(model=self.model, temperature=0, messages=msgs, **kw).choices[0].message
            if not m.tool_calls:
                return m.content or "", log
            msgs.append({"role": "assistant", "content": m.content, "tool_calls": [tc.model_dump() for tc in m.tool_calls]})
            for tc in m.tool_calls:
                args = json.loads(tc.function.arguments); out = HANDLERS[tc.function.name](**args)
                log.append({"tool": tc.function.name, "args": args, "result": out})
                msgs.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(out, ensure_ascii=False)})
        return "", log

class Mock:  # solo para validar el pipeline; NO usar para el informe
    def chat(self, user, tools=False, max_iter=6):
        name = re.search(r"ARCHIVO: (\S+)", user).group(1); g = GT[name]
        if not g["vulnerable"]: return '{"findings":[]}', []
        ev = (CASES / name).read_text().splitlines()[g["line"] - 1].strip()
        return json.dumps({"findings": [{"line": g["line"], "cwe": g["cwe"], "evidence": ev, "explanation": "mock"}]}), []

# ---------- evaluacion ----------
def parse(text):
    try:
        s, e = text.index("{"), text.rindex("}") + 1
        return json.loads(text[s:e]).get("findings", []), True
    except Exception:
        return [], False

def is_hallucination(f, name):
    src = (CASES / name).read_text(); n = len(src.splitlines())
    try:
        line = int(f.get("line")); ev = " ".join(str(f.get("evidence", "")).split())
    except Exception:
        return True
    return not (1 <= line <= n and CWE_RE.match(str(f.get("cwe", ""))) and ev and ev in " ".join(src.split()))

def score_file(name, findings):
    g = GT[name]; tp = fp = fn = hall = 0
    for f in findings:
        if is_hallucination(f, name): hall += 1
        ok = g["vulnerable"] and f.get("cwe") == g["cwe"] and abs(int(f.get("line", -99)) - g["line"]) <= 2 if str(f.get("line", "")).lstrip("-").isdigit() else False
        if ok: tp += 1
        else: fp += 1
    if g["vulnerable"] and tp == 0: fn = 1
    tp = min(tp, 1)
    return {"tp": tp, "fp": fp, "fn": fn, "hall": hall, "n_findings": len(findings), "flagged": len(findings) > 0}

def aggregate(rows):
    tp = sum(r["tp"] for r in rows); fp = sum(r["fp"] for r in rows); fn = sum(r["fn"] for r in rows)
    hall = sum(r["hall"] for r in rows); nf = sum(r["n_findings"] for r in rows)
    safe = [r for r in rows if not GT[r["file"]]["vulnerable"]]
    prec = tp / (tp + fp) if tp + fp else 0.0; rec = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
            "fpr_archivos_seguros": round(sum(r["flagged"] for r in safe) / len(safe), 3) if safe else 0.0,
            "tasa_alucinacion": round(hall / nf, 3) if nf else 0.0, "tp": tp, "fp": fp, "fn": fn, "hallucinated": hall, "findings": nf}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["sast", "llm", "hybrid"], required=True)
    ap.add_argument("--provider", choices=["anthropic", "openai", "mock"], default="anthropic")
    ap.add_argument("--model", default="")
    ap.add_argument("--base-url", default=None, help="p.ej. http://localhost:11434/v1 para Ollama")
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()

    agent = None
    if a.mode != "sast":
        agent = {"anthropic": lambda: Anthropic(a.model), "openai": lambda: OpenAICompat(a.model, a.base_url), "mock": Mock}[a.provider]()
    runs = 1 if a.mode == "sast" else a.runs
    tag = f"{a.mode}_{(a.model or a.provider).replace('/', '-').replace(':', '-')}"
    out = ROOT / "results" / f"{tag}_{datetime.datetime.now():%Y%m%d_%H%M%S}"; out.mkdir(parents=True)
    all_rows, per_run_flags = [], {n: [] for n in GT}

    with open(out / "transcripts.jsonl", "w") as tr:
        for run in range(1, runs + 1):
            for name in sorted(GT):
                t0 = time.time(); raw, log, ok = "", [], True
                if a.mode == "sast":
                    findings = [{"line": r["line"], "cwe": r["cwe"], "evidence": r["code"]} for r in tool_run_semgrep(name)]
                else:
                    prompt = f"ARCHIVO: {name}\n\n{read_numbered(name)}" if a.mode == "llm" else f"Audita el archivo {name}. Usa las herramientas disponibles y luego responde con el JSON final."
                    raw, log = agent.chat(prompt, tools=(a.mode == "hybrid"))
                    findings, ok = parse(raw)
                row = {"run": run, "file": name, "json_valido": ok, "latencia_s": round(time.time() - t0, 2), "tool_calls": len(log), **score_file(name, findings)}
                all_rows.append(row); per_run_flags[name].append(row["flagged"])
                tr.write(json.dumps({**row, "findings": findings, "raw": raw, "tool_log": log}, ensure_ascii=False) + "\n")
                print(f"run{run} {name:26s} hallazgos={row['n_findings']} tp={row['tp']} fp={row['fp']} fn={row['fn']} halluc={row['hall']} tools={row['tool_calls']}")

    m = aggregate(all_rows)
    m["consistencia"] = round(sum(len(set(v)) == 1 for v in per_run_flags.values()) / len(per_run_flags), 3)
    m["json_invalido"] = sum(not r["json_valido"] for r in all_rows)
    m["latencia_media_s"] = round(sum(r["latencia_s"] for r in all_rows) / len(all_rows), 2)
    m["tool_calls_total"] = sum(r["tool_calls"] for r in all_rows)
    m.update({"modo": a.mode, "modelo": "semgrep" if a.mode == "sast" else (a.model or a.provider), "corridas": runs, "archivos": len(GT)})
    json.dump(m, open(out / "metrics.json", "w"), indent=2, ensure_ascii=False)
    csv_path = ROOT / "results" / "summary.csv"; new = not csv_path.exists()
    with open(csv_path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(m)); new and w.writeheader(); w.writerow(m)
    print("\n== METRICAS =="); print(json.dumps(m, indent=2, ensure_ascii=False)); print("Evidencia en:", out)

if __name__ == "__main__":
    main()
