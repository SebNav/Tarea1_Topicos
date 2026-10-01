"""
 Actividad 2. Codigo para generar las figuras del informe.

 Grafica la frecuencia exacta y estimada (frecuencia.png), el error de la estimacion
 (error_frecuencia.png) y el delta f exacto y estimado (delta_f.png), guardandolas en
 resultados/figuras

 Se corre por terminal desde la carpeta Tarea1, despues de generar_ataques.py
"""

#%% rutas y variables
import os
import json
import pandas as pd
import matplotlib.pyplot as plt

DIR_EXACTO = "resultados/exacto"
DIR_SKETCH = "resultados/sketch"
DIR_FIG = "resultados/figuras"
os.makedirs(DIR_FIG, exist_ok=True)

ANCHOS = [256, 1024, 4096]
SEED = 1
W_DF = 256           # ancho usado en las figuras de Delta f (donde mas se nota el efecto)
COLOR_W = {256: "tab:blue", 1024: "tab:orange", 4096: "tab:green"}

with open("datos/ddos/gt_ddos_pps8000.json") as f:
    gt_ddos = json.load(f)
victima = gt_ddos["ataque"]["victima"]
ini_ddos, fin_ddos = gt_ddos["ventana_ataque_rel_s"]

with open("datos/scan/gt_scan_pps8000.json") as f:
    gt_scan = json.load(f)
atacante = gt_scan["ataque"]["atacante"]
ini_scan, fin_scan = gt_scan["ventana_ataque_rel_s"]

#%% Carga de datos

ex_ddos = pd.read_csv(f"{DIR_EXACTO}/ddos/dst_{victima}_pps8000.csv")
ex_scan = pd.read_csv(f"{DIR_EXACTO}/scan/src_{atacante}_pps8000.csv")

sk_ddos = {w: pd.read_csv(f"{DIR_SKETCH}/ddos8000_dst_w{w}_seed{SEED}.csv") for w in ANCHOS}
sk_scan = {w: pd.read_csv(f"{DIR_SKETCH}/scan8000_src_w{w}_seed{SEED}.csv") for w in ANCHOS}

# el CSV de bin/codigo no trae t_rel_s ni exact_f, se agregan desde el CSV
# exacto por "win", asi cada fila ya tiene todo lo que hace falta para graficar.
for w in ANCHOS:
    sk_ddos[w] = sk_ddos[w].merge(ex_ddos[["win", "t_rel_s", "exact_f"]], on="win")
    sk_scan[w] = sk_scan[w].merge(ex_scan[["win", "t_rel_s", "exact_f"]], on="win")

# una fila por ataque, para recorrer ambos con el mismo codigo: (verdad exacta,
# estimaciones por ancho, inicio, termino, nombre para el eje y)
ATAQUES = [
    (ex_ddos, sk_ddos, ini_ddos, fin_ddos, f"DDoS\nvíctima {victima}"),
    (ex_scan, sk_scan, ini_scan, fin_scan, f"Scan\natacante {atacante}"),
]
SKETCHES = [("f_cms", "Count-Min Sketch"), ("f_cs", "CountSketch")]

#%% Figura 1: frecuencia exacta vs. CMS y CS (DDoS arriba, scan abajo)

fig, ax = plt.subplots(2, 2, figsize=(11, 8), sharex=True, sharey=True)
for row, (ex, sk, ini, fin, nombre) in enumerate(ATAQUES):
    for col, (metrica, titulo) in enumerate(SKETCHES):
        a = ax[row, col]
        a.plot(ex["t_rel_s"], ex["exact_f"], color="black", linewidth=2.2, label="exacta")
        for w in ANCHOS:
            a.plot(sk[w]["t_rel_s"], sk[w][metrica], color=COLOR_W[w], linewidth=1.3, label=f"w={w}")
        a.axvline(ini, color="grey", linestyle="--", linewidth=1)
        a.axvline(fin, color="grey", linestyle="--", linewidth=1)
        a.set_xlim(ini - 60, fin + 60)
        a.grid(alpha=0.3)
        if row == 0:
            a.set_title(titulo)
        if col == 0:
            a.set_ylabel(f"{nombre}\nf(x)  [paquetes / ventana]")
        if row == 1:
            a.set_xlabel("t (s)")
ax[0, 0].legend(fontsize=8)
fig.suptitle("Frecuencia exacta vs. estimada")
fig.tight_layout()
fig.savefig(f"{DIR_FIG}/frecuencia.png", dpi=150)
print(f"guardado: {DIR_FIG}/frecuencia.png")

#%% Figura 2: error de la estimacion (f_hat - f_exacta), misma grilla

fig, ax = plt.subplots(2, 2, figsize=(11, 8), sharex=True)   # sin sharey: CMS y CS difieren en escala
for row, (ex, sk, ini, fin, nombre) in enumerate(ATAQUES):
    for col, (metrica, titulo) in enumerate(SKETCHES):
        a = ax[row, col]
        for w in ANCHOS:
            error = sk[w][metrica] - sk[w]["exact_f"]
            a.plot(sk[w]["t_rel_s"], error, color=COLOR_W[w], linewidth=1.3, label=f"w={w}")
        a.axhline(0, color="grey", linewidth=0.8)
        a.axvline(ini, color="grey", linestyle="--", linewidth=1)
        a.axvline(fin, color="grey", linestyle="--", linewidth=1)
        a.set_xlim(ini - 60, fin + 60)
        a.grid(alpha=0.3)
        if row == 0:
            a.set_title(titulo)
        if col == 0:
            a.set_ylabel(f"{nombre}\nf̂(x) − f(x)")
        if row == 1:
            a.set_xlabel("t (s)")
ax[0, 0].legend(fontsize=8)
fig.suptitle("Error de estimación por ancho (nota: CMS y CS NO comparten escala vertical)")
fig.tight_layout()
fig.savefig(f"{DIR_FIG}/error_frecuencia.png", dpi=150)
print(f"guardado: {DIR_FIG}/error_frecuencia.png")

#%% Figura 3: Delta f exacto, CountSketch y CMS-mediana (DDoS y scan, w=W_DF)

fig, ax = plt.subplots(1, 2, figsize=(11, 3.6), sharey=True)
for a, (ex, sk, ini, fin, nombre) in zip(ax, ATAQUES):
    d = sk[W_DF]
    a.plot(ex["t_rel_s"], ex["exact_delta"], color="black", linewidth=2.2, label="exacto")
    a.plot(d["t_rel_s"], d["df_cs"], color="tab:blue", linewidth=1.3, label="CountSketch")
    a.plot(d["t_rel_s"], d["df_cms_med"], color="tab:red", linewidth=1.3, label="CMS-mediana")
    a.axhline(0, color="grey", linewidth=0.8)
    a.axvline(ini, color="grey", linestyle="--", linewidth=1)
    a.axvline(fin, color="grey", linestyle="--", linewidth=1)
    a.set_xlim(ini - 60, fin + 60)
    a.set_xlabel("t (s)")
    a.set_title(nombre.replace("\n", ", "))
    a.grid(alpha=0.3)
ax[0].set_ylabel("Δf(x)  [paquetes]")
ax[0].legend(fontsize=8)
fig.tight_layout()
fig.savefig(f"{DIR_FIG}/delta_f.png", dpi=150)
print(f"guardado: {DIR_FIG}/delta_f.png")
