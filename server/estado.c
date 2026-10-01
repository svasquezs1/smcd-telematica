/*
 * Tabla de estado de la infraestructura (en memoria).
 * Ver estado.h para el contrato. Un solo mutex global protege todo.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "estado.h"
#include "log.h"

typedef enum { NODO_DESCONECTADO = 0, NODO_ACTIVO = 1, NODO_INACTIVO = 2 } estado_nodo_t;

typedef struct { time_t ts; char datos[MAX_DATOS]; } muestra_t;
typedef struct { time_t ts; char nodo[64]; char datos[MAX_DATOS]; } evento_t;

typedef struct {
    int           en_uso;
    char          id[64];
    char          tipo[16];
    char          ip[16];
    int           puerto;
    estado_nodo_t estado;
    unsigned long sesion;            /* sesión TCP vigente                    */
    time_t        ultima_actividad;  /* último registro o telemetría          */
    int           ultimo_id_udp;     /* mayor id de TELEMETRY aceptado        */
    muestra_t     hist[MAX_HIST];    /* historial circular de telemetría      */
    int           hist_n, hist_pos;
    int           ids_evento[MAX_IDS_EVENTO];  /* ids de EVENT_REQ recientes  */
    int           ids_n, ids_pos;
    int           num_eventos;
} nodo_t;

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static nodo_t    g_nodos[MAX_NODOS];
static evento_t  g_eventos[MAX_EVENTOS];
static int       g_ev_n = 0, g_ev_pos = 0;
static unsigned long g_sesion_seq = 0;

static const char *nombre_estado(estado_nodo_t e) {
    switch (e) {
        case NODO_ACTIVO:   return "ACTIVO";
        case NODO_INACTIVO: return "INACTIVO";
        default:            return "DESCONECTADO";
    }
}

/* ---- helpers (se llaman con el mutex tomado) ---- */

static nodo_t *buscar(const char *id) {
    for (int i = 0; i < MAX_NODOS; i++)
        if (g_nodos[i].en_uso && strcmp(g_nodos[i].id, id) == 0) return &g_nodos[i];
    return NULL;
}

static void push_evento(const char *nodo, const char *datos) {
    evento_t *e = &g_eventos[g_ev_pos];
    e->ts = time(NULL);
    snprintf(e->nodo, sizeof(e->nodo), "%s", nodo);
    snprintf(e->datos, sizeof(e->datos), "%s", datos);
    g_ev_pos = (g_ev_pos + 1) % MAX_EVENTOS;
    if (g_ev_n < MAX_EVENTOS) g_ev_n++;
}

/* Añade texto formateado a out sin desbordarlo. Devuelve 0 si ya no cabe. */
static int anexar(char *out, size_t n, size_t *len, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(out + *len, n - *len, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t) w >= n - *len) { out[*len] = '\0'; return 0; }
    *len += (size_t) w;
    return 1;
}

/* ---- API ---- */

int estado_registrar_nodo(const char *id, const char *tipo, const char *ip,
                          int puerto, unsigned long *sesion, int *reemplazo) {
    pthread_mutex_lock(&g_mtx);
    nodo_t *n = buscar(id);
    *reemplazo = 0;
    if (!n) {
        for (int i = 0; i < MAX_NODOS; i++) {
            if (!g_nodos[i].en_uso) { n = &g_nodos[i]; break; }
        }
        if (!n) { pthread_mutex_unlock(&g_mtx); return EST_LLENO; }
        memset(n, 0, sizeof(*n));
        n->en_uso = 1;
        snprintf(n->id, sizeof(n->id), "%s", id);
    } else if (n->estado != NODO_DESCONECTADO) {
        *reemplazo = 1;   /* el nodo reconecta antes de que detectemos su caída */
    }
    snprintf(n->tipo, sizeof(n->tipo), "%s", tipo);
    snprintf(n->ip, sizeof(n->ip), "%s", ip);
    n->puerto = puerto;
    n->estado = NODO_ACTIVO;
    n->sesion = ++g_sesion_seq;
    n->ultima_actividad = time(NULL);
    /* El nodo reinicia su contador de ids al reconectar: olvidamos los ids
     * anteriores para no confundir mensajes nuevos con duplicados. */
    n->ultimo_id_udp = 0;
    n->ids_n = n->ids_pos = 0;
    *sesion = n->sesion;
    pthread_mutex_unlock(&g_mtx);
    return EST_OK;
}

void estado_nodo_desconectado(const char *id, unsigned long sesion) {
    pthread_mutex_lock(&g_mtx);
    nodo_t *n = buscar(id);
    if (n && n->sesion == sesion && n->estado != NODO_DESCONECTADO) {
        n->estado = NODO_DESCONECTADO;
        push_evento(id, "tipo=nodo_desconectado;severidad=alta;origen=servidor");
        log_evento("WARNING", n->ip, n->puerto, "Nodo %s DESCONECTADO (cerro la conexion TCP)", id);
    }
    pthread_mutex_unlock(&g_mtx);
}

int estado_telemetria(const char *id, int msg_id, const char *datos,
                      const char *ip_origen, int *recuperado) {
    int rc = EST_OK;
    *recuperado = 0;
    pthread_mutex_lock(&g_mtx);
    nodo_t *n = buscar(id);
    if (!n || n->estado == NODO_DESCONECTADO) {
        rc = EST_NO_REGISTRADO;
    } else if (strcmp(n->ip, ip_origen) != 0) {
        rc = EST_ORIGEN_INVALIDO;           /* suplantación: otra IP dice ser el nodo */
    } else if (msg_id <= n->ultimo_id_udp) {
        rc = EST_DUPLICADO;                 /* repetido o llegó desordenado */
    } else {
        n->ultimo_id_udp = msg_id;
        muestra_t *m = &n->hist[n->hist_pos];
        m->ts = time(NULL);
        snprintf(m->datos, sizeof(m->datos), "%s", datos);
        n->hist_pos = (n->hist_pos + 1) % MAX_HIST;
        if (n->hist_n < MAX_HIST) n->hist_n++;
        n->ultima_actividad = m->ts;
        if (n->estado == NODO_INACTIVO) {
            n->estado = NODO_ACTIVO;
            *recuperado = 1;
            push_evento(id, "tipo=nodo_recuperado;severidad=info;origen=servidor");
        }
    }
    pthread_mutex_unlock(&g_mtx);
    return rc;
}

int estado_evento(const char *id, int msg_id, const char *datos) {
    int rc = EST_OK;
    pthread_mutex_lock(&g_mtx);
    nodo_t *n = buscar(id);
    if (!n || n->estado == NODO_DESCONECTADO) {
        rc = EST_NO_REGISTRADO;
    } else {
        int visto = 0;
        for (int i = 0; i < n->ids_n; i++)
            if (n->ids_evento[i] == msg_id) { visto = 1; break; }
        if (visto) {
            rc = EST_DUPLICADO;             /* reintento del nodo: no se guarda dos veces */
        } else {
            n->ids_evento[n->ids_pos] = msg_id;
            n->ids_pos = (n->ids_pos + 1) % MAX_IDS_EVENTO;
            if (n->ids_n < MAX_IDS_EVENTO) n->ids_n++;
            n->num_eventos++;
            n->ultima_actividad = time(NULL);
            push_evento(id, datos);
        }
    }
    pthread_mutex_unlock(&g_mtx);
    return rc;
}

void estado_revisar_inactividad(int timeout_s) {
    time_t ahora = time(NULL);
    pthread_mutex_lock(&g_mtx);
    for (int i = 0; i < MAX_NODOS; i++) {
        nodo_t *n = &g_nodos[i];
        if (!n->en_uso || n->estado != NODO_ACTIVO) continue;
        long silencio = (long) (ahora - n->ultima_actividad);
        if (silencio > timeout_s) {
            char datos[MAX_DATOS];
            n->estado = NODO_INACTIVO;
            snprintf(datos, sizeof(datos),
                     "tipo=nodo_inactivo;severidad=alta;origen=servidor;segundos_sin_reportar=%ld", silencio);
            push_evento(n->id, datos);
            log_evento("WARNING", n->ip, n->puerto,
                       "Nodo %s INACTIVO (%ld s sin telemetria, limite %d s)", n->id, silencio, timeout_s);
        }
    }
    pthread_mutex_unlock(&g_mtx);
}

/* ---- Consultas: formato "meta|datos" por línea (ver especificación) ---- */

int estado_listar(char *out, size_t n) {
    size_t len = 0;
    int cuenta = 0;
    time_t ahora = time(NULL);
    out[0] = '\0';
    pthread_mutex_lock(&g_mtx);
    for (int i = 0; i < MAX_NODOS; i++) {
        nodo_t *nd = &g_nodos[i];
        if (!nd->en_uso) continue;
        const char *ult = "";
        if (nd->hist_n > 0)
            ult = nd->hist[(nd->hist_pos + MAX_HIST - 1) % MAX_HIST].datos;
        if (!anexar(out, n, &len, "nodo=%s;tipo=%s;estado=%s;visto_hace=%ld;eventos=%d|%s\n",
                    nd->id, nd->tipo, nombre_estado(nd->estado),
                    (long) (ahora - nd->ultima_actividad), nd->num_eventos, ult))
            break;
        cuenta++;
    }
    pthread_mutex_unlock(&g_mtx);
    return cuenta;
}

int estado_historial(const char *id, int max, char *out, size_t n) {
    size_t len = 0;
    int cuenta = 0;
    time_t ahora = time(NULL);
    out[0] = '\0';
    pthread_mutex_lock(&g_mtx);
    nodo_t *nd = buscar(id);
    if (!nd) { pthread_mutex_unlock(&g_mtx); return -1; }
    if (max > nd->hist_n) max = nd->hist_n;
    for (int k = 0; k < max; k++) {            /* de la más reciente a la más antigua */
        muestra_t *m = &nd->hist[(nd->hist_pos + MAX_HIST - 1 - k) % MAX_HIST];
        if (!anexar(out, n, &len, "ts=%ld;hace=%ld|%s\n", (long) m->ts, (long) (ahora - m->ts), m->datos))
            break;
        cuenta++;
    }
    pthread_mutex_unlock(&g_mtx);
    return cuenta;
}

int estado_eventos(char *out, size_t n) {
    size_t len = 0;
    int cuenta = 0;
    time_t ahora = time(NULL);
    out[0] = '\0';
    pthread_mutex_lock(&g_mtx);
    for (int k = 0; k < g_ev_n; k++) {          /* del más reciente al más antiguo */
        evento_t *e = &g_eventos[(g_ev_pos + MAX_EVENTOS - 1 - k) % MAX_EVENTOS];
        if (!anexar(out, n, &len, "ts=%ld;hace=%ld;nodo=%s|%s\n",
                    (long) e->ts, (long) (ahora - e->ts), e->nodo, e->datos))
            break;
        cuenta++;
    }
    pthread_mutex_unlock(&g_mtx);
    return cuenta;
}
