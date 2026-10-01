"""
 Actividad 2. Codigo para generar la tabla resumen de la deteccion de ataques con CMS y CS.

 Calcula el MRE, los falsos positivos y negativos, la memoria y la latencia de deteccion,
 guardando la info en tabla_resumen.csv

 Se corre por terminal desde la carpeta Tarea1, despues de generar_ataques.py
"""

#%% rutas y variables
import os
import json
import numpy as np
import pandas as pd

TRAZA = "datos/base/traza.bin"
BIN_CODIGO = "bin/codigo"
DIR_EXACTO = "resultados/exacto"
DIR_SKETCH = "resultados/sketch"

ANCHOS = [256, 1024, 4096]
SEMILLAS = [1, 2, 3, 4, 5]

with open("datos/ddos/gt_ddos_pps8000.json") as f:
    gt_ddos = json.load(f)
victima = gt_ddos["ataque"]["victima"]
ini_ddos, fin_ddos = gt_ddos["ventana_ataque_rel_s"]

with open("datos/scan/gt_scan_pps8000.json") as f:
    gt_scan = json.load(f)
atacante = gt_scan["ataque"]["atacante"]
ini_scan, fin_scan = gt_scan["ventana_ataque_rel_s"]

#%% Memoria (la reporta el propio bin/codigo, no se recalcula aqui)

memoria_kib = {}                       # w -> KiB, por tipo de sketch (CMS o CS; son iguales)
tmp = "/tmp/mem_tabla_resumen.txt"
for w in ANCHOS:
    os.system(f"{BIN_CODIGO} {TRAZA} --key dst -d 5 -w {w} --seed 1 --query 1.2.3.4 "
              f"> /dev/null 2> {tmp}")
    linea = open(tmp).readline()               # "memoria (CMS+CS): 90.0 KiB  (d=5, ...)"
    kib_total = float(linea.split(":")[1].split("KiB")[0])
    memoria_kib[w] = kib_total / 2              # CMS y CS ocupan lo mismo cada uno
os.remove(tmp)

#%% Carga de datos

ex_ddos = pd.read_csv(f"{DIR_EXACTO}/ddos/dst_{victima}_pps8000.csv")
ex_scan = pd.read_csv(f"{DIR_EXACTO}/scan/src_{atacante}_pps8000.csv")

# J: ventanas afectadas por el ataque (seccion 6.2, punto 2 del enunciado)
J_ddos = ex_ddos.loc[(ex_ddos.t_rel_s > ini_ddos) & (ex_ddos.t_rel_s - 60 < fin_ddos)
                     & (ex_ddos.exact_f > 0), "win"]
J_scan = ex_scan.loc[(ex_scan.t_rel_s > ini_scan) & (ex_scan.t_rel_s - 60 < fin_scan)
                     & (ex_scan.exact_f > 0), "win"]

primera_exacta_ddos = ex_ddos.loc[ex_ddos.exact_hh == 1, "win"].min()
primera_exacta_scan = ex_scan.loc[ex_scan.exact_hh == 1, "win"].min()

# una fila por ataque, para recorrer los dos con el mismo codigo. El inicio del
# ataque es el parametro start de inject_attack.py (guardado en el JSON).
ATAQUES = [
    ("DDoS", ex_ddos, J_ddos, primera_exacta_ddos, "ddos8000_dst", ini_ddos),
    ("Scan", ex_scan, J_scan, primera_exacta_scan, "scan8000_src", ini_scan),
]

#%% Calculo de metricas (MRE, FP, FN, adelantos) por ataque x sketch x ancho

filas = []
for nombre_ataque, ex, J, primera_exacta, prefijo, ini in ATAQUES:
    # instante de la primera ventana con exact_hh = 1 en la salida de exact_hh
    t_det_exacta = ex.loc[ex.win == primera_exacta, "t_rel_s"].iloc[0]
    for w in ANCHOS:
        for sketch in ("cms", "cs"):
            mre_por_semilla = []
            fp = fn = 0
            primeras_deteccion = []
            t_det_sketch = []
            t_fp = set()
            for s in SEMILLAS:
                sk = pd.read_csv(f"{DIR_SKETCH}/{prefijo}_w{w}_seed{s}.csv")
                m = sk.merge(ex[["win", "t_rel_s", "exact_f", "exact_hh"]], on="win")

                mJ = m[m["win"].isin(J)]
                mre = (mJ[f"f_{sketch}"] - mJ["exact_f"]).abs() / mJ["exact_f"]
                mre_por_semilla.append(mre.mean())

                es_fp = (m[f"hh_{sketch}"] == 1) & (m["exact_hh"] == 0)
                fp += int(es_fp.sum())
                t_fp.update(m.loc[es_fp, "t_rel_s"].astype(int))
                fn += int(((m[f"hh_{sketch}"] == 0) & (m["exact_hh"] == 1)).sum())

                primeras_deteccion.append(m.loc[m[f"hh_{sketch}"] == 1, "win"].min())
                t_det_sketch.append(int(m.loc[m[f"hh_{sketch}"] == 1, "t_rel_s"].min()))

            adelantos = sum(1 for x in primeras_deteccion if x < primera_exacta)
            atrasos = sum(1 for x in primeras_deteccion if x > primera_exacta)

            filas.append({
                "ataque": nombre_ataque, "sketch": sketch.upper(), "w": w,
                "memoria_KiB": memoria_kib[w],
                "MRE_media": np.mean(mre_por_semilla), "MRE_std": np.std(mre_por_semilla, ddof=1),
                "FP": fp, "FN": fn,
                "n_semillas": len(SEMILLAS),
                # cuenta de semillas (de las n_semillas) en que la primera deteccion
                # del sketch cae antes / despues de la primera deteccion exacta
                "latencia adelanto": adelantos,
                "latencia atraso": atrasos,
                # instantes en segundos desde el primer paquete de la traza
                "t inicio ataque": int(ini),
                "t deteccion exacta": int(t_det_exacta),
                "t deteccion sketch (por semilla)": " ".join(str(x) for x in t_det_sketch),
                "t falsos positivos": " ".join(str(x) for x in sorted(t_fp)),
            })

tabla = pd.DataFrame(filas)

# Validacion de la alineacion: N de cada corrida identico al de exact_hh
iguales = total = 0
for nombre_ataque, ex, J, primera_exacta, prefijo, ini in ATAQUES:
    n_ex = ex.set_index("win")["N"]
    for w in ANCHOS:
        for s in SEMILLAS:
            n_sk = pd.read_csv(f"{DIR_SKETCH}/{prefijo}_w{w}_seed{s}.csv").set_index("win")["N"]
            iguales += int((n_ex == n_sk).all())
            total += 1
print(f"N identico a exact_hh en todas las ventanas: {iguales} de {total} corridas con ataque")

#%% Guardado de la tabla

print(tabla.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
tabla.to_csv("resultados/tabla_resumen.csv", index=False)
print("\nguardado: resultados/tabla_resumen.csv")
