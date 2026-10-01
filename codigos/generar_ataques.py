"""
 Actividad 2. Codigo para generar los ataques de ddos y scan con inject_attack.py (semilla 42)
 y evaluarlos con exact_hh y el Codigo creado utilizando CMS y CS.

 Realiza las 30 corridas del sketch (3 anchos, 5 semillas y 2 ataques), guardando la info
 en resultados/sketch

 Se corre por terminal desde la carpeta Tarea1.
"""

#%% rutas y variables
import os
import json
import pandas as pd

TRAZA_BASE   = "datos/base/traza.bin"
INJECT       = "python3 codigo_entregado/inject_attack.py"
EXACT_HH     = "codigo_entregado/exact_hh"
BIN_CODIGO   = "bin/codigo"

DIR_DDOS = "datos/ddos"
DIR_SCAN = "datos/scan"
DIR_EXACTO = "resultados/exacto"
DIR_SKETCH = "resultados/sketch"

D = 5
ANCHOS = [256, 1024, 4096]
SEMILLAS = [1, 2, 3, 4, 5]
PPS = 8000
INICIO = 300
DURACION = 30
SEED_ATAQUE = 42

for d in (DIR_DDOS, DIR_SCAN, f"{DIR_EXACTO}/ddos", f"{DIR_EXACTO}/scan", DIR_SKETCH):
    os.makedirs(d, exist_ok=True)

traza_ddos = f"{DIR_DDOS}/traza_ddos_pps{PPS}.bin"
gt_ddos    = f"{DIR_DDOS}/gt_ddos_pps{PPS}.json"
traza_scan = f"{DIR_SCAN}/traza_scan_pps{PPS}.bin"
gt_scan    = f"{DIR_SCAN}/gt_scan_pps{PPS}.json"

#%% Generar las trazas con ataque (inject_attack.py)

os.system(f"{INJECT} ddos --base {TRAZA_BASE} --out {traza_ddos} --gt {gt_ddos} "
          f"--start {INICIO} --duration {DURACION} --pps {PPS} --sources 4000 --seed {SEED_ATAQUE}")
os.system(f"{INJECT} scan --base {TRAZA_BASE} --out {traza_scan} --gt {gt_scan} "
          f"--start {INICIO} --duration {DURACION} --pps {PPS} --dst-count 60000 --seed {SEED_ATAQUE}")

with open(gt_ddos) as f:
    victima = json.load(f)["ataque"]["victima"]
with open(gt_scan) as f:
    atacante = json.load(f)["ataque"]["atacante"]
print(f"victima DDoS: {victima} | atacante scan: {atacante}")

#%% Verdad exacta (exact_hh) para cada ataque

query_ddos = f"{DIR_EXACTO}/ddos/dst_{victima}_pps{PPS}.csv"
win_ddos   = f"{DIR_EXACTO}/ddos/win_dst_pps{PPS}.csv"
query_scan = f"{DIR_EXACTO}/scan/src_{atacante}_pps{PPS}.csv"
win_scan   = f"{DIR_EXACTO}/scan/win_src_pps{PPS}.csv"

os.system(f"{EXACT_HH} {traza_ddos} --key dst -W 60 --delta 10 --phi 0.01 "
          f"--query {victima} --out-query {query_ddos} --out-windows {win_ddos}")
os.system(f"{EXACT_HH} {traza_scan} --key src -W 60 --delta 10 --phi 0.01 "
          f"--query {atacante} --out-query {query_scan} --out-windows {win_scan}")

#%% Corridas del sketch (3 anchos x 5 semillas x 2 ataques = 30 corridas)

for w in ANCHOS:
    for s in SEMILLAS:
        out_ddos = f"{DIR_SKETCH}/ddos{PPS}_dst_w{w}_seed{s}.csv"
        os.system(f"{BIN_CODIGO} {traza_ddos} --key dst -d {D} -w {w} --seed {s} "
                  f"--query {victima} > {out_ddos}")

        out_scan = f"{DIR_SKETCH}/scan{PPS}_src_w{w}_seed{s}.csv"
        os.system(f"{BIN_CODIGO} {traza_scan} --key src -d {D} -w {w} --seed {s} "
                  f"--query {atacante} > {out_scan}")

#%% Verificacion (N del sketch contra exact_hh, una muestra por ataque)

for nombre, win_csv, sk_csv in [
        ("DDoS", win_ddos, f"{DIR_SKETCH}/ddos{PPS}_dst_w256_seed1.csv"),
        ("Scan", win_scan, f"{DIR_SKETCH}/scan{PPS}_src_w256_seed1.csv")]:
    N_exacto = pd.read_csv(win_csv)["N"]
    N_sketch = pd.read_csv(sk_csv)["N"]
    if N_exacto.equals(N_sketch):
        print(f"{nombre}: N identico al de exact_hh en las {len(N_exacto)} ventanas")
    else:
        print(f"{nombre}: FALLA, N difiere de exact_hh")
