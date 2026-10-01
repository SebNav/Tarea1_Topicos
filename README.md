# Tarea 1 2026: Count-Min Sketch y CountSketch en ventana deslizante

Tópicos en Grandes Volúmenes de Datos. Sebastián Navarrete Caro.

El informe está en `Tarea1_Topicos_informe.pdf`.

## Contenido del repositorio

```
├── Tarea1_Topicos_informe.pdf
├── Makefile                  compila codigos/Codigo.cpp en bin/codigo
├── codigos/
│   ├── Codigo.cpp            CMS y CS con ventana deslizante (anillo de 6 subventanas)
│   ├── MurmurHash3.cpp/.h    funciones hash
│   ├── actividad1_codigo.py  validación en la traza sin ataques
│   ├── generar_ataques.py    trazas con ataque, exact_hh y las 30 corridas del sketch
│   ├── tabla_resumen.py      tabla resumen de la detección
│   ├── analisis_delta_f.py   análisis del cambio de frecuencia
│   └── Figuras.py            figuras del informe
└── codigo_entregado/         material entregado por el curso
    ├── pcap2bin.cpp          convierte la traza .pcap al formato binario
    ├── exact_hh.cpp          conteo exacto por ventana (referencia)
    ├── inject_attack.py      inyecta los ataques sintéticos
    ├── Makefile
    └── requirements.txt
```

No se incluyen las trazas. Las carpetas `datos/` y `resultados/` se crean al
reproducir los pasos de abajo.

## Traza y semillas

- Traza: MAWI Working Group Traffic Archive, samplepoint-F, 2018-12-03 14:00 (15 minutos).
  https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
- Semilla de los ataques (`inject_attack.py`): 42, igual para DDoS y scan.
- Semillas de los hashes de los sketches: 1 en la traza sin ataques y 1, 2, 3, 4 y 5 en las trazas con ataque.
- Sketches con d = 5 y w = 256, 1024 y 4096.

| Ataque | Parámetros de `inject_attack.py` | Clave | IP del ataque |
|---|---|---|---|
| DDoS | `--start 300 --duration 30 --pps 8000 --sources 4000 --seed 42` | dst | víctima 163.210.30.13 |
| Scan | `--start 300 --duration 30 --pps 8000 --dst-count 60000 --seed 42` | src | atacante 198.18.0.7 |

## Requisitos

- g++ con C++17 y make
- Python  con numpy, pandas, matplotlib y openpyxl

## Cómo reproducir los datos

Todos los comandos se ejecutan desde la carpeta raíz del repositorio.

**1. Compilar.**

```bash
make -C codigo_entregado     # pcap2bin y exact_hh
make                         # bin/codigo
```

**2. Descargar y convertir la traza** (una sola vez).

```bash
mkdir -p datos/crudo datos/base resultados/exacto/base
curl -L -C - -o datos/crudo/201812031400.pcap.gz \
    https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
zcat datos/crudo/201812031400.pcap.gz | ./codigo_entregado/pcap2bin \
    > datos/base/traza.bin 2> datos/base/pcap2bin.log
```

**3. Scripts**, en este orden. `actividad1_codigo.py` también calcula el
ranking exacto (top-k) de la traza sin ataques, del que se eligieron las claves
de rank 1, 10, 50, 100 y 250 de la primera ventana.

```bash
python3 codigos/actividad1_codigo.py    # Tablas 3 y 4 (Anexo)
python3 codigos/generar_ataques.py      # trazas con ataque, exact_hh y 30 corridas
python3 codigos/tabla_resumen.py        # Tabla 1
python3 codigos/analisis_delta_f.py     # Tabla 2
python3 codigos/Figuras.py              # Figuras 2, 3 y 4
```

## De dónde sale cada tabla y figura del informe

| Informe | Script | Archivo generado |
|---|---|---|
| Figura 1 (ventana y anillo) | dibujada a mano | |
| Figura 2 (frecuencia) | `Figuras.py` | `resultados/figuras/frecuencia.png` |
| Figura 3 (Δf) | `Figuras.py` | `resultados/figuras/delta_f.png` |
| Figura 4, Anexo (error) | `Figuras.py` | `resultados/figuras/error_frecuencia.png` |
| Tabla 1 (resumen de detección) | `tabla_resumen.py` | `resultados/tabla_resumen.csv` |
| Tabla 2 (Δf) | `analisis_delta_f.py` | `resultados/tabla_delta_f.csv` |
| Tablas 3 y 4, Anexo | `actividad1_codigo.py` | `resultados/sketch/actividad1_resumen.xlsx` |
| Memoria de la tabla exacta (59 MB) | `actividad1_codigo.py` | `resultados/exacto/base/resumen_query_dst.txt` |
| Paquetes inyectados (240.000) | `generar_ataques.py` | `datos/ddos/gt_ddos_pps8000.json` |

## Uso directo de bin/codigo

```bash
./bin/codigo datos/base/traza.bin --key dst -d 5 -w 1024 --seed 1 --query 202.12.82.146
```

Imprime por stdout un CSV con una fila por ventana y clave consultada
(`win,tau_us,key,N,T,f_cms,hh_cms,f_cs,hh_cs,df_cs,df_cms_med`) y la memoria
de los contadores por stderr.
