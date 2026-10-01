/*
 * Servidor central del sistema SMCD (Sistema de Monitoreo y Control Distribuido)
 * Fase 3 — Concurrencia, resiliencia y pruebas.
 *
 * Uso:   ./servidor <puerto> <archivoDeLogs>
 *
 * Variables de entorno opcionales (ver README):
 *   SMCD_TIMEOUT_NODO    segundos sin telemetria para marcar un nodo INACTIVO (15)
 *   SMCD_MAX_CONEXIONES  maximo de conexiones TCP simultaneas (200)
 *   SMCD_LDAP_URI, SMCD_LDAP_BASE   servicio de autenticacion (ver auth_ldap.c)
 *
 * ARQUITECTURA DE HILOS (ver Bloque 4):
 *   - hilo principal : accept() de conexiones TCP; por cada una crea un hilo.
 *   - hilo UDP       : recibe la telemetria de todos los nodos.
 *   - hilo monitor   : cada segundo detecta nodos que dejaron de reportar.
 *   - un hilo por cada conexion TCP (nodo o cliente de administracion).
 * Toda la informacion compartida vive en estado.c, protegida con un mutex.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "protocolo.h"
#include "estado.h"
#include "auth.h"
#include "log.h"

/* ---------------------------------------------------------------------- */
/* Parametros y temporizadores                                            */
/* ---------------------------------------------------------------------- */
#define TIMEOUT_RECV_S          10    /* granularidad de las lecturas TCP           */
#define TIMEOUT_HANDSHAKE_S     10    /* tiempo para identificarse (REG/AUTH)       */
#define TIMEOUT_CLIENTE_IDLE_S  300   /* un cliente de admin inactivo se desconecta */
#define MAX_ERRORES_SEGUIDOS    5     /* errores consecutivos antes de cerrar       */
#define MAX_INTENTOS_AUTH       3     /* intentos de autenticacion por conexion     */
#define STACK_HILO              (1024 * 1024)

static int g_timeout_nodo   = 15;
static int g_max_conexiones = 200;

static volatile sig_atomic_t g_running = 1;
static int g_conexiones = 0;
static pthread_mutex_t g_conn_mtx = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------------- */
/* Sesion: estado de UNA conexion TCP (cada hilo tiene la suya)           */
/* ---------------------------------------------------------------------- */
typedef enum { S_NUEVA, S_NODO, S_CLIENTE } sesion_tipo_t;

typedef struct {
    int           fd;
    char          ip[INET_ADDRSTRLEN];
    int           puerto;
    sesion_tipo_t tipo;                 /* maquina de estados de la conexion   */
    char          id[NMP_MAX_FROM];     /* id del nodo o nombre del usuario    */
    char          perfil[16];           /* "admin" / "viewer" (solo clientes)  */
    char          token[17];            /* identificador de sesion (clientes)  */
    unsigned long sesion_nodo;          /* sesion registrada en estado.c       */
    int           errores_seguidos;
    int           intentos_auth;
} sesion_t;

typedef struct { int fd; char ip[INET_ADDRSTRLEN]; int puerto; } conn_t;

/* ---------------------------------------------------------------------- */
/* Envio de respuestas con logging                                        */
/* ---------------------------------------------------------------------- */
static int enviar(sesion_t *s, int type, int id, const char *payload) {
    char vista[256];
    log_sanear(payload, vista, sizeof(vista));
    log_evento(type == TYPE_ERROR ? "WARNING" : "INFO", s->ip, s->puerto,
               "--> %s id=%d \"%s\"", nmp_type_name(type), id, vista);
    return nmp_send(s->fd, type, id, "servidor", payload) == NMP_OK ? 0 : -1;
}

static int enviar_error(sesion_t *s, int id, const char *codigo, const char *detalle) {
    char p[160];
    snprintf(p, sizeof(p), "codigo=%s;detalle=%s", codigo, detalle);
    return enviar(s, TYPE_ERROR, id, p);
}

/* Rechaza un mensaje con ERROR y cuenta el error. Devuelve 1 si hay que cerrar
 * la conexion (fallo al enviar o demasiados errores seguidos). */
static int rechazar(sesion_t *s, int id, const char *codigo, const char *detalle) {
    if (enviar_error(s, id, codigo, detalle) < 0) return 1;
    if (++s->errores_seguidos >= MAX_ERRORES_SEGUIDOS) {
        log_evento("WARNING", s->ip, s->puerto,
                   "Demasiados errores seguidos (%d): se cierra la conexion", s->errores_seguidos);
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Utilidades                                                             */
/* ---------------------------------------------------------------------- */
static int env_int(const char *nombre, int defecto, int min, int max) {
    const char *v = getenv(nombre);
    if (!v || !*v) return defecto;
    char *fin;
    long n = strtol(v, &fin, 10);
    if (*fin != '\0' || n < min || n > max) {
        fprintf(stderr, "Aviso: %s=%s invalido, se usa %d\n", nombre, v, defecto);
        return defecto;
    }
    return (int) n;
}

/* Token de sesion aleatorio (16 hex) leido de /dev/urandom. 0 si ok. */
static int generar_token(char *out) {
    unsigned char b[8];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(b, 1, sizeof(b), f);
    fclose(f);
    if (n != sizeof(b)) return -1;
    for (int i = 0; i < 8; i++) sprintf(out + 2 * i, "%02x", b[i]);
    return 0;
}

static int tipo_nodo_valido(const char *t) {
    return strcmp(t, "iot") == 0 || strcmp(t, "red") == 0 || strcmp(t, "servidor") == 0;
}

/* ---------------------------------------------------------------------- */
/* Manejadores de cada primitiva del protocolo NMP                        */
/* Devuelven 1 si la conexion debe cerrarse, 0 si debe continuar.         */
/* ---------------------------------------------------------------------- */

/* REG_REQ: un nodo se registra. Payload: tipo=<iot|red|servidor> */
static int h_reg(sesion_t *s, const nmp_message_t *m) {
    char tipo[16];
    if (nmp_get_field(m->payload, "tipo", tipo, sizeof(tipo)) < 0 || !tipo_nodo_valido(tipo))
        return rechazar(s, m->id, "PARAMETRO_INVALIDO", "tipo_requerido_iot_red_servidor");

    unsigned long sesion;
    int reemplazo;
    int rc = estado_registrar_nodo(m->from, tipo, s->ip, s->puerto, &sesion, &reemplazo);
    if (rc == EST_LLENO) {
        enviar_error(s, m->id, "TABLA_LLENA", "no_caben_mas_nodos");
        return 1;
    }
    if (reemplazo)
        log_evento("WARNING", s->ip, s->puerto,
                   "Nodo %s ya estaba conectado: la nueva conexion reemplaza a la anterior", m->from);

    s->tipo = S_NODO;
    snprintf(s->id, sizeof(s->id), "%s", m->from);
    s->sesion_nodo = sesion;
    s->errores_seguidos = 0;

    char p[64];
    snprintf(p, sizeof(p), "resultado=ok;sesion=%lu", sesion);
    log_evento("INFO", s->ip, s->puerto, "Nodo %s registrado (tipo=%s)", m->from, tipo);
    return enviar(s, TYPE_REG_ACK, m->id, p) < 0;
}

/* EVENT_REQ: evento critico de un nodo ya registrado. Payload: tipo=... */
static int h_event(sesion_t *s, const nmp_message_t *m) {
    char tipo[48];
    if (m->len >= MAX_DATOS || nmp_get_field(m->payload, "tipo", tipo, sizeof(tipo)) < 0)
        return rechazar(s, m->id, "PARAMETRO_INVALIDO", "evento_requiere_campo_tipo_y_menos_de_256_bytes");

    int rc = estado_evento(s->id, m->id, m->payload);
    if (rc == EST_NO_REGISTRADO) {
        enviar_error(s, m->id, "NO_REGISTRADO", "sesion_de_nodo_ya_no_es_valida");
        return 1;
    }
    s->errores_seguidos = 0;
    if (rc == EST_DUPLICADO) {
        log_evento("WARNING", s->ip, s->puerto,
                   "EVENT_REQ duplicado de %s (id=%d): se confirma de nuevo sin guardarlo otra vez",
                   s->id, m->id);
        return enviar(s, TYPE_EVENT_ACK, m->id, "resultado=ok;duplicado=1") < 0;
    }
    char vista[256];
    log_sanear(m->payload, vista, sizeof(vista));
    log_evento("WARNING", s->ip, s->puerto, "EVENTO CRITICO de %s: %s", s->id, vista);
    return enviar(s, TYPE_EVENT_ACK, m->id, "resultado=ok") < 0;
}

/* AUTH_REQ: un cliente de administracion se autentica contra LDAP.
 * Payload: usuario=<u>;password=<p>   (valores codificados con %XX) */
static int h_auth(sesion_t *s, const nmp_message_t *m) {
    char usuario[64], password[256];
    if (nmp_get_field(m->payload, "usuario", usuario, sizeof(usuario)) < 0 ||
        nmp_get_field(m->payload, "password", password, sizeof(password)) < 0)
        return rechazar(s, m->id, "PARAMETRO_INVALIDO", "se_requiere_usuario_y_password");
    if (strcmp(usuario, m->from) != 0)
        return rechazar(s, m->id, "IDENTIDAD_INVALIDA", "FROM_debe_coincidir_con_usuario");

    char perfil[16];
    int rc = auth_validar(usuario, password, perfil, sizeof(perfil));
    memset(password, 0, sizeof(password));   /* no dejamos la clave en memoria */

    if (rc == AUTH_SERVICIO_NO_DISPONIBLE) {
        log_evento("ERROR", s->ip, s->puerto, "Servicio de autenticacion no disponible");
        return enviar_error(s, m->id, "SERVICIO_AUTH_NO_DISPONIBLE", "intente_mas_tarde") < 0;
    }
    if (rc != AUTH_OK) {
        s->intentos_auth++;
        log_evento("WARNING", s->ip, s->puerto, "Autenticacion RECHAZADA para '%s' (intento %d/%d)",
                   usuario, s->intentos_auth, MAX_INTENTOS_AUTH);
        if (enviar(s, TYPE_AUTH_ACK, m->id, "resultado=rechazo;motivo=credenciales_invalidas") < 0) return 1;
        if (s->intentos_auth >= MAX_INTENTOS_AUTH) {
            log_evento("WARNING", s->ip, s->puerto, "Maximo de intentos de autenticacion: se cierra");
            return 1;
        }
        return 0;
    }
    if (generar_token(s->token) < 0) {
        enviar_error(s, m->id, "ERROR_INTERNO", "no_se_pudo_crear_la_sesion");
        return 1;
    }
    s->tipo = S_CLIENTE;
    snprintf(s->id, sizeof(s->id), "%s", usuario);
    snprintf(s->perfil, sizeof(s->perfil), "%s", perfil);
    s->errores_seguidos = 0;

    char p[96];
    snprintf(p, sizeof(p), "resultado=ok;perfil=%s;sesion=%s", perfil, s->token);
    log_evento("INFO", s->ip, s->puerto, "Usuario '%s' autenticado (perfil=%s)", usuario, perfil);
    return enviar(s, TYPE_AUTH_ACK, m->id, p) < 0;
}

/* QUERY_REQ: consulta de un cliente autenticado.
 * Payload: sesion=<token>;consulta=<estado|historial|eventos>[;nodo=<id>][;n=<1..10>]
 * Perfiles: viewer -> estado, historial.   admin -> ademas eventos. */
static int h_query(sesion_t *s, const nmp_message_t *m) {
    char sesion[32], consulta[16];
    if (nmp_get_field(m->payload, "sesion", sesion, sizeof(sesion)) < 0 ||
        strcmp(sesion, s->token) != 0)
        return rechazar(s, m->id, "SESION_INVALIDA", "token_de_sesion_incorrecto");
    if (nmp_get_field(m->payload, "consulta", consulta, sizeof(consulta)) < 0)
        return rechazar(s, m->id, "PARAMETRO_INVALIDO", "falta_el_campo_consulta");

    static const size_t CAP = NMP_MAX_PAYLOAD - 160;
    char cuerpo[NMP_MAX_PAYLOAD - 160];
    char resp[NMP_MAX_PAYLOAD];
    int registros;

    if (strcmp(consulta, "estado") == 0) {
        registros = estado_listar(cuerpo, CAP);
    } else if (strcmp(consulta, "historial") == 0) {
        char nodo[NMP_MAX_FROM], nstr[8];
        int n = MAX_HIST;
        if (nmp_get_field(m->payload, "nodo", nodo, sizeof(nodo)) < 0 || !nmp_id_valido(nodo))
            return rechazar(s, m->id, "PARAMETRO_INVALIDO", "historial_requiere_nodo");
        if (nmp_get_field(m->payload, "n", nstr, sizeof(nstr)) == 0) {
            char *fin;
            long v = strtol(nstr, &fin, 10);
            if (*nstr == '\0' || *fin != '\0' || v < 1 || v > MAX_HIST)
                return rechazar(s, m->id, "PARAMETRO_INVALIDO", "n_debe_estar_entre_1_y_10");
            n = (int) v;
        }
        registros = estado_historial(nodo, n, cuerpo, CAP);
        if (registros < 0)
            return rechazar(s, m->id, "NODO_DESCONOCIDO", "el_nodo_no_existe");
    } else if (strcmp(consulta, "eventos") == 0) {
        if (strcmp(s->perfil, "admin") != 0) {
            log_evento("WARNING", s->ip, s->puerto,
                       "ACCESO DENEGADO: '%s' (perfil %s) pidio la consulta 'eventos'", s->id, s->perfil);
            return rechazar(s, m->id, "ACCESO_DENEGADO", "la_consulta_eventos_requiere_perfil_admin");
        }
        registros = estado_eventos(cuerpo, CAP);
    } else {
        return rechazar(s, m->id, "PARAMETRO_INVALIDO", "consulta_desconocida");
    }

    s->errores_seguidos = 0;
    snprintf(resp, sizeof(resp), "resultado=ok;consulta=%s;registros=%d\n%s", consulta, registros, cuerpo);
    return enviar(s, TYPE_QUERY_RESP, m->id, resp) < 0;
}

/* ---------------------------------------------------------------------- */
/* Despacho: aplica la maquina de estados de la conexion (ver wiki)       */
/* ---------------------------------------------------------------------- */
static int procesar(sesion_t *s, const nmp_message_t *m) {
    if (m->type < TYPE_REG_REQ || m->type > TYPE_ERROR)
        return rechazar(s, m->id, "TIPO_DESCONOCIDO", "tipo_de_mensaje_no_definido");
    if (!nmp_payload_valido(m->payload))
        return rechazar(s, m->id, "PARAMETRO_INVALIDO", "payload_mal_formado");
    if (s->tipo != S_NUEVA && strcmp(m->from, s->id) != 0)
        return rechazar(s, m->id, "IDENTIDAD_INVALIDA", "FROM_no_coincide_con_la_sesion");

    switch (s->tipo) {
    case S_NUEVA:
        if (m->type == TYPE_REG_REQ)   return h_reg(s, m);
        if (m->type == TYPE_AUTH_REQ)  return h_auth(s, m);
        if (m->type == TYPE_EVENT_REQ) return rechazar(s, m->id, "NO_REGISTRADO", "registrese_primero_con_REG_REQ");
        if (m->type == TYPE_QUERY_REQ) return rechazar(s, m->id, "NO_AUTENTICADO", "autentiquese_primero_con_AUTH_REQ");
        break;
    case S_NODO:
        if (m->type == TYPE_EVENT_REQ) return h_event(s, m);
        if (m->type == TYPE_REG_REQ)   return rechazar(s, m->id, "FUERA_DE_SECUENCIA", "el_nodo_ya_esta_registrado");
        break;
    case S_CLIENTE:
        if (m->type == TYPE_QUERY_REQ) return h_query(s, m);
        if (m->type == TYPE_AUTH_REQ)  return rechazar(s, m->id, "FUERA_DE_SECUENCIA", "el_cliente_ya_esta_autenticado");
        break;
    }
    if (m->type == TYPE_TELEMETRY)
        return rechazar(s, m->id, "FUERA_DE_SECUENCIA", "la_telemetria_solo_se_envia_por_UDP");
    return rechazar(s, m->id, "FUERA_DE_SECUENCIA", "mensaje_no_valido_en_este_estado");
}

/* ---------------------------------------------------------------------- */
/* Hilo de una conexion TCP                                               */
/* ---------------------------------------------------------------------- */
static void configurar_socket_tcp(int fd) {
    struct timeval rcv = { TIMEOUT_RECV_S, 0 }, snd = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof(rcv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof(snd));
    /* Keepalive: detecta pares muertos (cable desconectado, maquina caida)
     * en conexiones largas que pasan mucho rato sin enviar nada. */
    int on = 1, idle = 30, intvl = 10, cnt = 3;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
}

static void *hilo_conexion(void *arg) {
    conn_t *c = (conn_t *) arg;
    sesion_t s;
    memset(&s, 0, sizeof(s));
    s.fd = c->fd;
    s.puerto = c->puerto;
    snprintf(s.ip, sizeof(s.ip), "%s", c->ip);
    s.tipo = S_NUEVA;
    free(c);

    configurar_socket_tcp(s.fd);
    log_evento("INFO", s.ip, s.puerto, "Nueva conexion TCP aceptada");

    int ocioso = 0;
    while (g_running) {
        nmp_message_t msg;
        int rc = nmp_recv(s.fd, &msg);

        if (rc == NMP_OK) {
            ocioso = 0;
            char vista[256];
            log_sanear(msg.payload, vista, sizeof(vista));
            log_evento("INFO", s.ip, s.puerto, "<-- %s id=%d from=%s \"%s\"",
                       nmp_type_name(msg.type), msg.id, msg.from, vista);
            if (procesar(&s, &msg)) break;
            continue;
        }
        if (rc == NMP_ERR_TIMEOUT) {
            ocioso += TIMEOUT_RECV_S;
            if (s.tipo == S_NUEVA && ocioso >= TIMEOUT_HANDSHAKE_S) {
                log_evento("WARNING", s.ip, s.puerto,
                           "Timeout: la conexion no se identifico en %d s", TIMEOUT_HANDSHAKE_S);
                enviar_error(&s, 0, "TIMEOUT", "no_se_identifico_a_tiempo");
                break;
            }
            if (s.tipo == S_CLIENTE && ocioso >= TIMEOUT_CLIENTE_IDLE_S) {
                log_evento("INFO", s.ip, s.puerto, "Cliente '%s' inactivo %d s: se desconecta", s.id, ocioso);
                break;
            }
            continue;   /* un nodo puede pasar mucho rato sin enviar por TCP */
        }
        if (rc == NMP_ERR_FORMATO) {
            /* Tras un error de formato el flujo TCP queda desincronizado:
             * respondemos ERROR y cerramos esta conexion (no el servidor). */
            log_evento("WARNING", s.ip, s.puerto, "Mensaje con formato invalido: se cierra la conexion");
            enviar_error(&s, 0, "FORMATO_INVALIDO", "cabecera_o_LEN_incorrectos");
            break;
        }
        break;   /* NMP_ERR_CERRADA: el otro extremo se fue */
    }

    if (s.tipo == S_NODO) estado_nodo_desconectado(s.id, s.sesion_nodo);
    if (s.tipo == S_NUEVA)
        log_evento("INFO", s.ip, s.puerto, "Conexion TCP cerrada");
    else
        log_evento("INFO", s.ip, s.puerto, "Conexion TCP cerrada (%s %s)",
                   s.tipo == S_NODO ? "nodo" : "usuario", s.id);
    close(s.fd);

    pthread_mutex_lock(&g_conn_mtx);
    g_conexiones--;
    pthread_mutex_unlock(&g_conn_mtx);
    return NULL;
}

/* ---------------------------------------------------------------------- */
/* Hilo UDP: telemetria (fire-and-forget, nunca se responde)              */
/* ---------------------------------------------------------------------- */
static void *hilo_udp(void *arg) {
    int fd = *(int *) arg;
    char buf[2048];

    while (g_running) {
        struct sockaddr_in rem;
        socklen_t rl = sizeof(rem);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &rem, &rl);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            log_evento("ERROR", "-", 0, "recvfrom UDP fallo: %s", strerror(errno));
            usleep(100000);
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &rem.sin_addr, ip, sizeof(ip));
        int puerto = ntohs(rem.sin_port);

        nmp_message_t msg;
        if (nmp_parse_buffer(buf, (int) n, &msg) != NMP_OK) {
            log_evento("WARNING", ip, puerto, "Datagrama UDP con formato invalido (%zd bytes): descartado", n);
            continue;
        }
        char vista[256];
        log_sanear(msg.payload, vista, sizeof(vista));
        log_evento("INFO", ip, puerto, "<-- %s id=%d from=%s \"%s\"",
                   nmp_type_name(msg.type), msg.id, msg.from, vista);

        if (msg.type != TYPE_TELEMETRY) {
            log_evento("WARNING", ip, puerto, "Tipo %s no esta permitido por UDP: descartado", nmp_type_name(msg.type));
            continue;
        }
        if (msg.len == 0 || msg.len >= MAX_DATOS || !nmp_payload_valido(msg.payload)) {
            log_evento("WARNING", ip, puerto, "TELEMETRY de %s con parametros invalidos: descartada", msg.from);
            continue;
        }

        int recuperado;
        int rc = estado_telemetria(msg.from, msg.id, msg.payload, ip, &recuperado);
        switch (rc) {
        case EST_OK:
            if (recuperado) log_evento("INFO", ip, puerto, "Nodo %s RECUPERADO: volvio a reportar", msg.from);
            break;
        case EST_DUPLICADO:
            log_evento("WARNING", ip, puerto, "TELEMETRY de %s repetida o desordenada (id=%d): descartada", msg.from, msg.id);
            break;
        case EST_ORIGEN_INVALIDO:
            log_evento("WARNING", ip, puerto, "TELEMETRY de %s descartada: la IP no coincide con la del nodo registrado", msg.from);
            break;
        default:
            log_evento("WARNING", ip, puerto, "TELEMETRY de %s descartada: nodo desconocido o no registrado", msg.from);
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------- */
/* Hilo monitor: detecta nodos que dejaron de reportar telemetria          */
/* ---------------------------------------------------------------------- */
static void *hilo_monitor(void *arg) {
    (void) arg;
    while (g_running) {
        sleep(1);
        estado_revisar_inactividad(g_timeout_nodo);
    }
    return NULL;
}

/* ---------------------------------------------------------------------- */
static void al_recibir_senal(int sig) { (void) sig; g_running = 0; }

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <puerto> <archivoDeLogs>\n", argv[0]);
        return 1;
    }
    char *fin;
    long puerto = strtol(argv[1], &fin, 10);
    if (*argv[1] == '\0' || *fin != '\0' || puerto < 1 || puerto > 65535) {
        fprintf(stderr, "Puerto invalido: %s (debe estar entre 1 y 65535)\n", argv[1]);
        return 1;
    }
    if (log_iniciar(argv[2]) < 0) {
        perror("No se pudo abrir el archivo de logs");
        return 1;
    }
    g_timeout_nodo   = env_int("SMCD_TIMEOUT_NODO", 15, 2, 3600);
    g_max_conexiones = env_int("SMCD_MAX_CONEXIONES", 200, 1, 5000);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = al_recibir_senal;          /* sin SA_RESTART: interrumpe accept/select */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* --- socket TCP --- */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) { perror("socket TCP"); return 1; }
    int opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t) puerto);
    if (bind(tcp_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) { perror("bind TCP"); return 1; }
    if (listen(tcp_fd, 128) < 0) { perror("listen"); return 1; }

    /* --- socket UDP (mismo numero de puerto; los espacios de puertos son independientes) --- */
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { perror("socket UDP"); return 1; }
    struct timeval t1 = { 1, 0 };
    setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &t1, sizeof(t1));
    if (bind(udp_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) { perror("bind UDP"); return 1; }

    log_evento("INFO", "0.0.0.0", (int) puerto,
               "Servidor SMCD iniciado en el puerto %ld (TCP y UDP). Timeout de nodos: %d s. Max conexiones: %d",
               puerto, g_timeout_nodo, g_max_conexiones);

    pthread_t th_udp, th_mon;
    pthread_create(&th_udp, NULL, hilo_udp, &udp_fd);
    pthread_create(&th_mon, NULL, hilo_monitor, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, STACK_HILO);

    /* --- bucle principal: aceptar conexiones y delegarlas a un hilo cada una --- */
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tcp_fd, &rfds);
        struct timeval espera = { 1, 0 };       /* para revisar g_running cada segundo */
        int r = select(tcp_fd + 1, &rfds, NULL, NULL, &espera);
        if (r < 0) { if (errno == EINTR) continue; perror("select"); break; }
        if (r == 0) continue;

        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int fd = accept(tcp_fd, (struct sockaddr *) &cli, &cl);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED) continue;
            log_evento("ERROR", "-", 0, "accept fallo: %s", strerror(errno));
            usleep(100000);
            continue;
        }

        conn_t *c = malloc(sizeof(*c));
        if (!c) { close(fd); continue; }
        c->fd = fd;
        inet_ntop(AF_INET, &cli.sin_addr, c->ip, sizeof(c->ip));
        c->puerto = ntohs(cli.sin_port);

        pthread_mutex_lock(&g_conn_mtx);
        int lleno = (g_conexiones >= g_max_conexiones);
        if (!lleno) g_conexiones++;
        pthread_mutex_unlock(&g_conn_mtx);

        if (lleno) {
            log_evento("WARNING", c->ip, c->puerto, "Conexion rechazada: limite de %d conexiones", g_max_conexiones);
            nmp_send(fd, TYPE_ERROR, 0, "servidor", "codigo=SERVIDOR_OCUPADO;detalle=limite_de_conexiones");
            close(fd);
            free(c);
            continue;
        }
        pthread_t th;
        if (pthread_create(&th, &attr, hilo_conexion, c) != 0) {
            log_evento("ERROR", c->ip, c->puerto, "No se pudo crear el hilo de la conexion");
            pthread_mutex_lock(&g_conn_mtx);
            g_conexiones--;
            pthread_mutex_unlock(&g_conn_mtx);
            close(fd);
            free(c);
        }
    }

    log_evento("INFO", "0.0.0.0", (int) puerto, "Senal de parada recibida: cerrando el servidor");
    g_running = 0;
    pthread_join(th_udp, NULL);
    pthread_join(th_mon, NULL);
    close(tcp_fd);
    close(udp_fd);
    log_evento("INFO", "0.0.0.0", (int) puerto, "Servidor detenido");
    log_cerrar();
    return 0;
}
