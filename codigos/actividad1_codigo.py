"""
 Actividad 1. Codigo para validar CMS y CS contra exact_hh en la traza sin ataques,
 usando 10 claves fijas (5 de destino y 5 de origen) y los anchos w = 256, 1024 y 4096.

 Calcula el error absoluto y relativo de CMS y CS, guardando la info en actividad1_errores.csv
 y el resumen por clave en actividad1_resumen.xlsx

 Se corre por terminal desde la carpeta Tarea1.
"""

#%% rutas y variables
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

TRAZA      = "datos/base/traza.bin"
EXACT_HH   = "codigo_entregado/exact_hh"
BIN_CODIGO = "bin/codigo"
DIR_EXACTO = "resultados/exacto/base"
DIR_SKETCH = "resultados/sketch"
DIR_FIG    = "resultados/figuras"

D = 5
ANCHOS = [256, 1024, 4096]
SEED = 1

# Claves elegidas utilizando el archivo resultados/exacto/base/topk_{dst,src}.csv,
# Se eligieron las IP dst y src para el rank 1,10,50,100,250 de la primera ventana
CLAVES_DST = [
    "202.12.82.146",   # rank 1
    "204.93.236.31",   # rank 10
    "163.210.11.14",   # rank 50
    "163.210.52.208",  # rank 100
    "203.83.98.61",    # rank 250
]
CLAVES_SRC = [
    "203.83.117.211",  # rank 1
    "74.221.94.120",   # rank 10
    "17.242.168.74",   # rank 50
    "173.0.177.137",   # rank 100
    "54.25.99.110",    # rank 250
]

query_dst = f"{DIR_EXACTO}/query_dst.csv"
query_src = f"{DIR_EXACTO}/query_src.csv"

os.makedirs(DIR_EXACTO, exist_ok=True)
os.makedirs(DIR_SKETCH, exist_ok=True)
os.makedirs(DIR_FIG, exist_ok=True)

#%% Ranking exacto (top-k) de la traza base, usado para elegir las claves de arriba

os.system(f"{EXACT_HH} {TRAZA} --key dst -W 60 --delta 10 --phi 0.01 --topk 1000 "
          f"--out-windows {DIR_EXACTO}/win_dst.csv --out-topk {DIR_EXACTO}/topk_dst.csv "
          f"> {DIR_EXACTO}/resumen_dst.txt")
os.system(f"{EXACT_HH} {TRAZA} --key src -W 60 --delta 10 --phi 0.01 --topk 1000 "
          f"--out-windows {DIR_EXACTO}/win_src.csv --out-topk {DIR_EXACTO}/topk_src.csv "
          f"> {DIR_EXACTO}/resumen_src.txt")

#%% Verificacion y Calculo de datos (correr exact_hh y bin/codigo)

queries_dst = " ".join(f"--query {ip}" for ip in CLAVES_DST)
queries_src = " ".join(f"--query {ip}" for ip in CLAVES_SRC)

# verdad exacta: una corrida por dimension, sirve para los 3 anchos. El resumen
# que imprime exact_hh (claves activas, memoria de su tabla) se guarda en un txt.
os.system(f"{EXACT_HH} {TRAZA} --key dst -W 60 --delta 10 --phi 0.01 "
          f"--out-query {query_dst} {queries_dst} > {DIR_EXACTO}/resumen_query_dst.txt")
os.system(f"{EXACT_HH} {TRAZA} --key src -W 60 --delta 10 --phi 0.01 "
          f"--out-query {query_src} {queries_src} > {DIR_EXACTO}/resumen_query_src.txt")

# bin/codigo: una corrida por (dimension, ancho). bin/codigo no tiene opcion out,
# la salida siempre va por stdout, asi que se redirige a un archivo con ">".
archivos_sketch = {}                      # (dim, w) -> ruta del CSV
for w in ANCHOS:
    out_dst = f"{DIR_SKETCH}/base_dst_w{w}_seed{SEED}.csv"
    os.system(f"{BIN_CODIGO} {TRAZA} --key dst -d {D} -w {w} --seed {SEED} "
              f"{queries_dst} > {out_dst}")
    archivos_sketch[("dst", w)] = out_dst

    out_src = f"{DIR_SKETCH}/base_src_w{w}_seed{SEED}.csv"
    os.system(f"{BIN_CODIGO} {TRAZA} --key src -d {D} -w {w} --seed {SEED} "
              f"{queries_src} > {out_src}")
    archivos_sketch[("src", w)] = out_src

#%% Calculo de errores

tablas = []
for (dim, w), out_csv in archivos_sketch.items():
    exacto_csv = query_dst if dim == "dst" else query_src
    ex = pd.read_csv(exacto_csv)[["win", "key", "exact_f"]].rename(columns={"exact_f": "f_exact"})
    sk = pd.read_csv(out_csv)[["win", "key", "f_cms", "f_cs"]]
    m = ex.merge(sk, on=["win", "key"])
    m = m[m["f_exact"] > 0].copy()               # el error relativo no se define si f_exact = 0

    m["err_abs_cms"] = m["f_cms"] - m["f_exact"]
    m["err_rel_cms"] = m["err_abs_cms"].abs() / m["f_exact"]
    m["err_abs_cs"] = m["f_cs"] - m["f_exact"]
    m["err_rel_cs"] = m["err_abs_cs"].abs() / m["f_exact"]
    m["campo"] = dim          # "src" o "dst": campo del paquete usado como clave (--key)
    m["w"] = w
    tablas.append(m)

errores = pd.concat(tablas, ignore_index=True)

# Validacion de la alineacion: N de cada corrida debe ser identico al de exact_hh
for (dim, w), out_csv in archivos_sketch.items():
    exacto_csv = query_dst if dim == "dst" else query_src
    n_ex = pd.read_csv(exacto_csv).groupby("win")["N"].first()
    n_sk = pd.read_csv(out_csv).groupby("win")["N"].first()
    print(f"N {dim} w={w}: identico a exact_hh en {int((n_ex == n_sk).sum())} de {len(n_ex)} ventanas")

viol = int((errores["err_abs_cms"] < 0).sum())
print(f"CMS nunca subestima: {viol} violaciones de {len(errores)} filas")

resumen = errores.groupby("w").agg(
    cms_mediana=("err_rel_cms", "median"),
    cms_p95=("err_rel_cms", lambda x: np.percentile(x, 95)),
    cs_mediana=("err_rel_cs", "median"),
    cs_p95=("err_rel_cs", lambda x: np.percentile(x, 95)),
    cms_abs_mediana=("err_abs_cms", lambda x: x.abs().median()),
    cs_abs_mediana=("err_abs_cs", lambda x: x.abs().median()),
)
print("\nError por ancho (agregando las 10 claves y las 84 ventanas):")
print(resumen.to_string(float_format=lambda x: f"{x:.4f}"))

# La memoria ocupada por los contadores (CMS + CS) no se calcula aqui: la reporta
# el propio bin/codigo por stderr en cada corrida ("memoria (CMS+CS): ... KiB"),
# asi que no queda una segunda cuenta en Python que se pueda desincronizar de la
# estructura real de Ventana en Codigo.cpp.

#%% Resumen por clave (una fila por IP, para comparar entre anchos)

# Error absoluto y relativo: media +- desviacion estandar entre ventanas. Una
# desviacion alta en el error relativo indica que la frecuencia de esa clave
# varia mucho de una ventana a otra.
resumen_clave = errores.groupby(["campo", "key", "w"]).agg(
    f_exact_medio=("f_exact", "mean"),
    err_abs_cms_media=("err_abs_cms", lambda x: x.abs().mean()),
    err_abs_cms_std=("err_abs_cms", lambda x: x.abs().std()),
    err_rel_cms_media=("err_rel_cms", "mean"),
    err_rel_cms_std=("err_rel_cms", "std"),
    err_abs_cs_media=("err_abs_cs", lambda x: x.abs().mean()),
    err_abs_cs_std=("err_abs_cs", lambda x: x.abs().std()),
    err_rel_cs_media=("err_rel_cs", "mean"),
    err_rel_cs_std=("err_rel_cs", "std"),
).reset_index()
resumen_clave = resumen_clave.sort_values(["campo", "f_exact_medio"], ascending=[True, False])

#%% Guardado de datos

errores.to_csv(f"{DIR_SKETCH}/actividad1_errores.csv", index=False)
print(f"\nguardado: {DIR_SKETCH}/actividad1_errores.csv ({len(errores)} filas)")

# una hoja por ancho, para poder comparar las claves lado a lado sin que la tabla
# quede demasiado ancha ni mezclada entre los tres w
with pd.ExcelWriter(f"{DIR_SKETCH}/actividad1_resumen.xlsx") as writer:
    for w in ANCHOS:
        hoja = resumen_clave[resumen_clave["w"] == w].drop(columns="w")
        hoja.to_excel(writer, sheet_name=f"w={w}", index=False)
print(f"guardado: {DIR_SKETCH}/actividad1_resumen.xlsx (hojas: {', '.join(f'w={w}' for w in ANCHOS)})")

#%% Tabla en imagen (una por ancho, para verlas rapido sin abrir el Excel)

columnas = ["campo", "key", "f exacta [paquetes]\n(media)",
            "Error abs. CMS [paquetes]\n(media ± std)", "Error rel. CMS\n(media ± std)",
            "Error abs. CS [paquetes]\n(media ± std)", "Error rel. CS\n(media ± std)"]
for w in ANCHOS:
    hoja = resumen_clave[resumen_clave["w"] == w]
    filas = []
    for _, r in hoja.iterrows():
        filas.append([
            r.campo, r.key, f"{r.f_exact_medio:,.0f}",
            f"{r.err_abs_cms_media:,.0f} ± {r.err_abs_cms_std:,.0f}", f"{r.err_rel_cms_media:.3f} ± {r.err_rel_cms_std:.3f}",
            f"{r.err_abs_cs_media:,.0f} ± {r.err_abs_cs_std:,.0f}", f"{r.err_rel_cs_media:.3f} ± {r.err_rel_cs_std:.3f}",
        ])

    fig, ax = plt.subplots(figsize=(12, 0.45 * len(filas) + 1))
    ax.axis("off")
    tabla_png = ax.table(cellText=filas, colLabels=columnas, loc="center", cellLoc="center")
    tabla_png.auto_set_font_size(False)
    tabla_png.set_fontsize(9)
    tabla_png.scale(1, 1.8)
    ax.set_title(f"Actividad 1, error CMS y CS, w={w}", pad=20)
    fig.tight_layout()
    ruta = f"{DIR_FIG}/actividad1_tabla_w{w}.png"
    fig.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"guardado: {ruta}")
