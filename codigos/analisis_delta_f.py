"""
 Actividad 2. Codigo para analizar el cambio de frecuencia (delta f) de la clave de cada ataque.

 Busca el mayor incremento y decremento exacto, y calcula el error de CS y CMS-mediana en las
 ventanas de evento y estables, guardando la info en tabla_delta_f.csv

 Se corre por terminal desde la carpeta Tarea1, despues de generar_ataques.py
"""

#%% rutas y variables
import json
import numpy as np
import pandas as pd

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

ex_ddos = pd.read_csv(f"{DIR_EXACTO}/ddos/dst_{victima}_pps8000.csv").dropna(subset=["exact_delta"])
ex_scan = pd.read_csv(f"{DIR_EXACTO}/scan/src_{atacante}_pps8000.csv").dropna(subset=["exact_delta"])

# una fila por ataque, para recorrer los dos con el mismo codigo
ATAQUES = [
    ("DDoS", ex_ddos, ini_ddos, fin_ddos, "ddos8000_dst"),
    ("Scan", ex_scan, ini_scan, fin_scan, "scan8000_src"),
]

#%% Mayor incremento y mayor decremento (valor exacto)

for nombre, ex, ini, fin, prefijo in ATAQUES:
    fila_max = ex.loc[ex.exact_delta.idxmax()]
    fila_min = ex.loc[ex.exact_delta.idxmin()]
    print(f"{nombre}: mayor incremento exacto = {fila_max.exact_delta:+.0f} en t={fila_max.t_rel_s:.0f} s "
          f"| mayor decremento exacto = {fila_min.exact_delta:+.0f} en t={fila_min.t_rel_s:.0f} s")

#%% Error de CS y CMS-mediana contra Delta f exacto (ventanas de evento vs. estables)

filas = []
for nombre, ex, ini, fin, prefijo in ATAQUES:
    # ventanas de evento: entra o sale una subventana con paquetes del ataque
    evento = ex[((ex.t_rel_s > ini) & (ex.t_rel_s <= ini + 30)) |
                ((ex.t_rel_s > fin + 30) & (ex.t_rel_s <= fin + 60))]["win"]
    estables = ex[~ex.win.isin(evento)]["win"]

    fila_max = ex.loc[ex.exact_delta.idxmax()]
    fila_min = ex.loc[ex.exact_delta.idxmin()]
    for w in ANCHOS:
        mae_evento_cs, mae_evento_cms, mae_estable_cs, mae_estable_cms = [], [], [], []
        for s in SEMILLAS:
            sk = pd.read_csv(f"{DIR_SKETCH}/{prefijo}_w{w}_seed{s}.csv").dropna(subset=["df_cs"])
            m = sk.merge(ex[["win", "exact_delta"]], on="win")

            mev = m[m.win.isin(evento)]
            mae_evento_cs.append((mev.df_cs - mev.exact_delta).abs().mean())
            mae_evento_cms.append((mev.df_cms_med - mev.exact_delta).abs().mean())

            mes = m[m.win.isin(estables)]
            mae_estable_cs.append((mes.df_cs - mes.exact_delta).abs().mean())
            mae_estable_cms.append((mes.df_cms_med - mes.exact_delta).abs().mean())

        filas.append({
            "ataque": nombre, "w": w,
            "max incremento exacto": int(fila_max.exact_delta), "t max incremento": int(fila_max.t_rel_s),
            "max decremento exacto": int(fila_min.exact_delta), "t max decremento": int(fila_min.t_rel_s),
            "MAE_evento_CS": np.mean(mae_evento_cs), "MAE_evento_CS_std": np.std(mae_evento_cs, ddof=1),
            "MAE_evento_CMSmed": np.mean(mae_evento_cms), "MAE_evento_CMSmed_std": np.std(mae_evento_cms, ddof=1),
            "MAE_estable_CS": np.mean(mae_estable_cs), "MAE_estable_CS_std": np.std(mae_estable_cs, ddof=1),
            "MAE_estable_CMSmed": np.mean(mae_estable_cms), "MAE_estable_CMSmed_std": np.std(mae_estable_cms, ddof=1),
        })

tabla = pd.DataFrame(filas)
print()
print(tabla.to_string(index=False, float_format=lambda x: f"{x:.1f}"))

#%% Guardado

tabla.to_csv("resultados/tabla_delta_f.csv", index=False)
print("\nguardado: resultados/tabla_delta_f.csv")
