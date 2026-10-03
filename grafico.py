import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COLORES = ["#2E75B6", "#ED7D31", "#70AD47"]  # azul, naranja, verde

# Ultima fila de cada combinacion (modo, modelo)
filas = {}
for r in csv.DictReader(open("results/summary.csv", encoding="utf-8")):
    filas[(r["modo"], r["modelo"])] = r

modelos = []
for r in filas.values():
    if r["modo"] != "sast" and r["modelo"] not in modelos:
        modelos.append(r["modelo"])  # Modelo A primero, luego Modelo B (orden de ejecucion)
orden = sorted(filas.values(), key=lambda r: (r["modo"] != "sast", modelos.index(r["modelo"]) if r["modelo"] in modelos else -1, r["modo"] != "llm"))
etiquetas = ["SAST\n(Semgrep)" if r["modo"] == "sast" else f'{r["modelo"]}\n{"LLM solo" if r["modo"] == "llm" else "Híbrido"}' for r in orden]
f = lambda k: [float(r[k]) for r in orden]
json_inv = [int(r["json_invalido"]) / (int(r["archivos"]) * int(r["corridas"])) for r in orden]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))
n, w = len(orden), 0.26
x = list(range(n))

# Panel 1: desempeno
for i, (k, nombre, hatch) in enumerate([("precision", "Precisión", ""), ("recall", "Recall", "//"), ("f1", "F1", "..")]):
    barras = ax1.bar([p + (i - 1) * w for p in x], f(k), w, label=nombre, color=COLORES[i], edgecolor="black", linewidth=0.8)
    for b in barras:
        ax1.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.01, f"{b.get_height():.2f}", ha="center", fontsize=7)
ax1.set_xticks(x); ax1.set_xticklabels(etiquetas, fontsize=8)
ax1.set_ylim(0, 1.1); ax1.set_ylabel("Valor"); ax1.set_title("Desempeño por configuración")
ax1.legend(); ax1.grid(axis="y", linestyle=":", alpha=0.6)

# Panel 2: errores
for i, (vals, nombre, hatch) in enumerate([(f("fpr_archivos_seguros"), "FPR (archivos seguros)", ""), (f("tasa_alucinacion"), "Tasa de alucinación", "//"), (json_inv, "Respuestas JSON inválidas", "..")]):
    barras = ax2.bar([p + (i - 1) * w for p in x], vals, w, label=nombre, color=COLORES[i], edgecolor="black", linewidth=0.8)
    for b in barras:
        ax2.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.01, f"{b.get_height():.2f}", ha="center", fontsize=7)
ax2.set_xticks(x); ax2.set_xticklabels(etiquetas, fontsize=8)
ax2.set_ylim(0, 1.1); ax2.set_ylabel("Proporción"); ax2.set_title("Errores por configuración")
ax2.legend(); ax2.grid(axis="y", linestyle=":", alpha=0.6)

plt.tight_layout()
plt.savefig("results/grafico_metricas.png", dpi=200)
print("Listo: results/grafico_metricas.png")