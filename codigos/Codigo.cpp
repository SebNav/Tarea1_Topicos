//  Tarea 1 2026: Count-Min Sketch y CountSketch en ventana deslizante.
//
//
// Compilación:
//     g++ -O2 -march=native -std=c++17 -Wall -Wextra -o codigo Codigo.cpp
//
// Uso:
//     ./codigo traza.bin
//


#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cmath>
#include <array>
#include <algorithm>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

//Hashear
#include <random>
#include <vector>
#include "MurmurHash3.h"


#pragma pack(push, 1)
struct Record {
    uint64_t ts_us;              // microsegundos desde epoch
    uint32_t src, dst;           // IPv4 como entero a.b.c.d = a<<24 | b<<16 | c<<8 | d
    uint16_t sport, dport, len;  // No se utilizan
    uint8_t proto, flags;        // No se utilizan
};
#pragma pack(pop)
static_assert(sizeof(Record) == 24, "el registro debe ocupar 24 bytes");



static bool parse_ipv4(const char *s, uint32_t *out) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}


//  W = 60 s, p = 10 s, m = W/p = 6.
constexpr uint64_t W_US = 60 * 1000000; // Tamaño de ventana
constexpr uint64_t P_US = 10 * 1000000; //Tamaño de subventana
constexpr uint64_t M    = W_US / P_US;



static std::string ip_to_string(uint32_t v) {
    char buf[16];
    snprintf(buf, sizeof buf, "%u.%u.%u.%u", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255);
    return std::string(buf);
}
// lectura de la traza
// mmap de solo lectura el archivo se trata como un arreglo de Record.
struct Trace {
    const Record *r = nullptr;
    size_t n = 0;
    void *addr = nullptr;
    size_t bytes = 0;
};

static Trace map_trace(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); exit(1); }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }
    if (st.st_size % (off_t)sizeof(Record)) {
        fprintf(stderr, "error: el tamaño no es múltiplo de 24 B\n");
        exit(1);
    }
    void *p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    close(fd);                       // el mapeo sigue válido tras cerrar el descriptor
    madvise(p, st.st_size, MADV_SEQUENTIAL);
    Trace t;
    t.addr = p;
    t.bytes = st.st_size;
    t.r = (const Record *)p;
    t.n = st.st_size / sizeof(Record);
    return t;
}



struct Hashes {
    std::vector<uint32_t> semillas;       // una semilla por fila del sketch (columna)
    std::vector<uint32_t> semillas_signo; // otras d semillas, para el signo de CountSketch

    Hashes(size_t d, uint64_t seed) {
        std::mt19937_64 rng(seed);
        for (size_t j = 0; j < d; ++j)
            semillas.push_back((uint32_t)rng());
        for (size_t j = 0; j < d; ++j)
            semillas_signo.push_back((uint32_t)rng());
    }

    uint32_t col(uint32_t clave, size_t j, uint32_t w) const {
        uint32_t h;
        MurmurHash3_x86_32(&clave, sizeof(clave), semillas[j], &h);
        return h % w;
    }

    int signo(uint32_t clave, size_t j) const {  // +1 o -1, con semilla distinta a la de la columna
        uint32_t h;
        MurmurHash3_x86_32(&clave, sizeof(clave), semillas_signo[j], &h);
        return (h & 1) ? +1 : -1;
    }
};

// Mediana de una lista de valores
static int32_t mediana(std::vector<int32_t> z) {
    std::sort(z.begin(), z.end());
    size_t n = z.size();
    if (n % 2 == 1) return z[n / 2];
    return (z[n / 2 - 1] + z[n / 2]) / 2;
}

struct Sketch {
    size_t d, w;
    std::vector<std::vector<int32_t>> C;  // C[fila=d][columna=w]

    Sketch(size_t d_, size_t w_) : d(d_), w(w_), C(d_, std::vector<int32_t>(w_, 0)) {} //Se inicializan en 0 la 'matriz dw'

    void insertar(uint32_t clave, const Hashes &H) {
        for (size_t j = 0; j < d; ++j)
            C[j][H.col(clave, j, (uint32_t)w)]++;
    }

    void insertar_cs(uint32_t clave, const Hashes &H) {   // CountSketch: suma +1 o -1
        for (size_t j = 0; j < d; ++j)
            C[j][H.col(clave, j, (uint32_t)w)] += H.signo(clave, j);
    }

    int32_t estimar_cs(uint32_t clave, const Hashes &H) const {   // CountSketch: mediana de s*C
        std::vector<int32_t> z;                                   // una estimacion por fila
        for (size_t j = 0; j < d; ++j)
            z.push_back(H.signo(clave, j) * C[j][H.col(clave, j, (uint32_t)w)]);
        return mediana(z);
    }

    int32_t estimar_mediana(uint32_t clave, const Hashes &H) const {   // "CMS-mediana": mediana de las celdas, sin signo
        std::vector<int32_t> z;
        for (size_t j = 0; j < d; ++j)
            z.push_back(C[j][H.col(clave, j, (uint32_t)w)]);
        return mediana(z);
    }

    int32_t estimar(uint32_t clave, const Hashes &H) const {
        int32_t m = C[0][H.col(clave, 0, (uint32_t)w)];
        for (size_t j = 1; j < d; ++j)
            m = std::min(m, C[j][H.col(clave, j, (uint32_t)w)]);
        return m;
    }

    void sumar(const Sketch &o) {
        for (size_t j = 0; j < d; ++j)
            for (size_t c = 0; c < w; ++c)
                C[j][c] += o.C[j][c];
    }

    void restar(const Sketch &o) {
        for (size_t j = 0; j < d; ++j)
            for (size_t c = 0; c < w; ++c)
                C[j][c] -= o.C[j][c];
    }

    void limpiar() {
        for (size_t j = 0; j < d; ++j)
            std::fill(C[j].begin(), C[j].end(), 0);
    }
};




// Esctructura Ventana anillos
struct Ventana{

    uint64_t N = 0; // Cantidad total de paquetes en la ventana
    std::array<uint64_t, M> Nsub{}; //Cantidad de paquetes por subventana

    Hashes H;                    // funciones hash, compartidas por todos los sketches

    std::vector<Sketch> CMS_sub; // Count-Min sketch de cada subventana
    Sketch CMS_A;                // Count-Min de los ultimos 60 s
    std::vector<Sketch> CS_sub;  // CountSketch sketch de cada subventana
    Sketch CS_A;                 // CountSketch de los ultimos 60 s

    // Cambio de frecuencia entre ventanas consecutivas dA = sub entrante - sub saliente
    Sketch CMS_saliente, CMS_dA; // Count-Min copia de la subventana que sale, y la diferencia dA
    Sketch CS_saliente, CS_dA;   // CountSketch lo mismo

    Ventana(size_t d, size_t w, uint64_t seed)
        : H(d, seed), CMS_sub(M, Sketch(d, w)), CMS_A(d, w), CS_sub(M, Sketch(d, w)), CS_A(d, w),
          CMS_saliente(d, w), CMS_dA(d, w), CS_saliente(d, w), CS_dA(d, w) {}

    // Count-Min
    void CMS_agregar(size_t r, uint32_t clave){
        CMS_sub[r].insertar(clave, H);
        CMS_A.insertar(clave, H);
    }

    void CMS_expirar(size_t r){                // saca la subventana r del agregado
        CMS_saliente = CMS_sub[r];             // se guarda antes de limpiarla, para calcular dA
        CMS_A.restar(CMS_sub[r]);
    }

    void CMS_delta(size_t r){                  // dA = sub[r] entrante - la saliente (ya guardada)
        CMS_dA = CMS_sub[r];
        CMS_dA.restar(CMS_saliente);
    }

    void CMS_limpiar(size_t r){                // deja la ranura r lista para reutilizarla
        CMS_sub[r].limpiar();
    }

    //  CountSketch
    void CS_agregar(size_t r, uint32_t clave){
        CS_sub[r].insertar_cs(clave, H);
        CS_A.insertar_cs(clave, H);
    }

    void CS_expirar(size_t r){
        CS_saliente = CS_sub[r];
        CS_A.restar(CS_sub[r]);
    }

    void CS_delta(size_t r){
        CS_dA = CS_sub[r];
        CS_dA.restar(CS_saliente);
    }

    void CS_limpiar(size_t r){
        CS_sub[r].limpiar();
    }

    // Un paquete entra / una subventana sale (conteo exacto + los dos sketches)
    void agregar(size_t r, uint32_t clave){

        Nsub[r]++;
        N++;

        CMS_agregar(r, clave);
        CS_agregar(r, clave);

    }

    void expirar(size_t r){

        N = N - Nsub[r];
        Nsub[r] = 0;

        CMS_expirar(r);
        CS_expirar(r);

        CMS_limpiar(r);
        CS_limpiar(r);

    }

    // Se llama despues de cargar la subventana nueva en la ranura r (que es la que se acaba de expirar)
    void delta(size_t r){

        CMS_delta(r);
        CS_delta(r);

    }

    // Memoria ocupada por los contadores de CMS + CS, en KiB. Cuenta las matrices
    // que de verdad mantiene esta Ventana (6 sub + agregado + saliente + dA, por
    // cada tipo), asi que si esa lista cambia, esta cuenta cambia sola con ella.
    double memoria_kib() const {
        size_t n_matrices = CMS_sub.size() + CS_sub.size()   // 6 + 6
                          + 6;                                // CMS_A, CS_A, *_saliente, *_dA
        return n_matrices * CMS_A.d * CMS_A.w * sizeof(int32_t) / 1024.0;
    }

};





int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "uso: %s traza.bin [--key src|dst] [-d N] [-w N] [--seed N] --query IP ...\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];

    //  argumentos (valores por defecto entre parentesis en el mensaje de uso)
    std::string key = "dst";
    size_t d = 5, w = 1024;
    uint64_t seed = 1;
    std::vector<uint32_t> claves;  // IPs a consultar

    for (int j = 2; j < argc; ++j) {
        std::string a = argv[j];
        auto next = [&]() -> const char * {        // mismo patron que exact_hh
            if (j + 1 >= argc) { fprintf(stderr, "falta valor para %s\n", a.c_str()); exit(2); }
            return argv[++j];
        };
        if      (a == "--key")   key  = next();
        else if (a == "-d")      d    = atoi(next());
        else if (a == "-w")      w    = atoi(next());
        else if (a == "--seed")  seed = atoll(next());
        else if (a == "--query") {
            uint32_t ip;
            if (!parse_ipv4(next(), &ip)) { fprintf(stderr, "IP invalida en --query\n"); return 2; }
            claves.push_back(ip);
        }
        else { fprintf(stderr, "opcion no reconocida: %s\n", argv[j]); return 2; }
    }
    if (claves.empty() || d == 0 || w == 0 || (key != "src" && key != "dst")) {
        fprintf(stderr, "uso: %s traza.bin [--key src|dst] [-d N] [-w N] [--seed N] --query IP ...\n", argv[0]);
        return 2;
    }
    bool usar_src = (key == "src"); // campo del paquete que se hashea

    uint64_t q      = 0;
    uint64_t ranura = 0;
    Ventana V(d, w, seed);
    fprintf(stderr, "memoria (CMS+CS): %.1f KiB  (d=%zu, w=%zu, seed=%" PRIu64 ")\n",
            V.memoria_kib(), d, w, seed);

    Trace t = map_trace(path);

    uint64_t t_0 = t.r[0].ts_us;

    uint64_t tau    = t_0 + W_US;
    //printf("%" PRIu64 "\n", t_0);
    size_t i = 0;                        // indice sobre la traza
    uint64_t t_fin = t.r[t.n - 1].ts_us; // ultimo timestamp de la traza

    printf("win,tau_us,key,N,T,f_cms,hh_cms,f_cs,hh_cs,df_cs,df_cms_med\n");

    // Cada looop es una evaluacion. En k = 0 (precarga) no hay nada que expirar.
    for (size_t k = 0; tau <= t_fin; ++k, tau += P_US) {

        if (k > 0) V.expirar((k - 1) % M);         // sale la subventana q = k

        //Carga de datos a ventana
        while (i < t.n && t.r[i].ts_us <= tau) {   // entra solo el trafico nuevo
            const Record &paquete = t.r[i];
            i++;
            q = (paquete.ts_us - t_0 + P_US - 1) / P_US;
            if (q == 0) continue;
            ranura = (q - 1) % M;
            uint32_t ip_paquete;                   // la IP del paquete que se hashea
            if (usar_src) ip_paquete = paquete.src;
            else          ip_paquete = paquete.dst;
            V.agregar(ranura, ip_paquete);
        }

        if (k > 0) V.delta((k - 1) % M);           // dA = subventana entrante - saliente

        uint64_t T = (V.N + 99) / 100;             // umbral ceil(0.01 * N)

        for (uint32_t clave : claves) {            // una fila por cada IP consultada
            int64_t f  = V.CMS_A.estimar(clave, V.H);  // frecuencia estimada de la IP en la ventana
            int     hh = (f >= (int64_t)T);        // 1 si es heavy hitter

            int64_t f_cs = V.CS_A.estimar_cs(clave, V.H);   // estimacion con CountSketch
            if (f_cs < 0) f_cs = 0;                         // el negativo se trunca solo al reportar
            int     hh_cs = (f_cs >= (int64_t)T);

            printf("%zu,%" PRIu64 ",%s,%" PRIu64 ",%" PRIu64 ",%" PRId64 ",%d,%" PRId64 ",%d",
                   k, tau, ip_to_string(clave).c_str(), V.N, T, f, hh, f_cs, hh_cs);

            if (k > 0) {    // cambio de frecuencia (sin truncar)
                int64_t df_cs  = V.CS_dA.estimar_cs(clave, V.H);
                int64_t df_cms = V.CMS_dA.estimar_mediana(clave, V.H);
                printf(",%" PRId64 ",%" PRId64 "\n", df_cs, df_cms);
            } else {
                printf(",,\n");          
            }
        }
    }

    munmap(t.addr, t.bytes);
    return 0;
}
