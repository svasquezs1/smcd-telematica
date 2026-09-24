/*
 * Servidor central del sistema SMCD (Sistema de Monitoreo y Control Distribuido)
 * Fase 2 — Implementación de comunicación básica.
 *
 * Alcance de esta fase (ver Fase de Desarrollo en la wiki):
 *   - Sockets TCP (registro de nodos, eventos, autenticación, consultas)
 *   - Socket UDP (telemetría periódica)
 *   - Multiplexado con select() para no bloquearse en un solo cliente
 *   - Reglas básicas del protocolo NMP (secuencia REG_REQ antes de EVENT_REQ, etc.)
 *
 * Explícitamente FUERA de alcance en esta fase (se implementa en Fase 3):
 *   - Concurrencia real con hilos (pthread) y mutex
 *   - Autenticación real contra LDAP (aquí hay un placeholder documentado)
 *
 * Uso:
 *   ./servidor <puerto> <archivoDeLogs>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "protocolo.h"

#define MAX_NODOS 50
#define MAX_CLIENTES_TCP 10

typedef struct {
    char   id[NMP_MAX_FROM];
    char   ip[INET_ADDRSTRLEN];
    int    puerto;
    int    registrado;
    time_t ultima_actividad;
    char   ultima_telemetria[256];
    int    num_eventos;
} nodo_t;

static nodo_t nodos[MAX_NODOS];
static int num_nodos = 0;
static FILE *log_file = NULL;

/* ---------------------------------------------------------------------- */
/* Logging: a consola y a archivo, con timestamp e IP:puerto del origen,   */
/* tal como lo exige el enunciado del proyecto.                            */
/* ---------------------------------------------------------------------- */
static void log_evento(const char *nivel, const char *ip, int puerto, const char *detalle) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    printf("[%s] [%s] [%s:%d] %s\n", timestamp, nivel, ip, puerto, detalle);

    if (log_file) {
        fprintf(log_file, "[%s] [%s] [%s:%d] %s\n", timestamp, nivel, ip, puerto, detalle);
        fflush(log_file);
    }
}

/* ---------------------------------------------------------------------- */
/* Tabla de estado de nodos (en memoria, sin protección con mutex todavía  */
/* porque en esta fase el servidor es de un solo hilo — ver Bloque 4).     */
/* ---------------------------------------------------------------------- */
static nodo_t *buscar_nodo(const char *id) {
    for (int i = 0; i < num_nodos; i++) {
        if (strcmp(nodos[i].id, id) == 0) return &nodos[i];
    }
    return NULL;
}

static nodo_t *buscar_o_crear_nodo(const char *id) {
    nodo_t *existente = buscar_nodo(id);
    if (existente) return existente;
    if (num_nodos >= MAX_NODOS) return NULL;

    nodo_t *n = &nodos[num_nodos++];
    memset(n, 0, sizeof(nodo_t));
    strncpy(n->id, id, sizeof(n->id) - 1);
    return n;
}

/* ---------------------------------------------------------------------- */
/* Manejo de mensajes TCP: aplica las reglas básicas de secuencia del      */
/* protocolo NMP (ver especificación en la wiki).                          */
/* ---------------------------------------------------------------------- */
static void manejar_mensaje_tcp(int fd, const char *ip, int puerto, nmp_message_t *msg) {
    char detalle[256];

    switch (msg->type) {

        case TYPE_REG_REQ: {
            nodo_t *n = buscar_o_crear_nodo(msg->from);
            if (!n) {
                nmp_send(fd, TYPE_ERROR, msg->id, "servidor", "tabla_de_nodos_llena");
                snprintf(detalle, sizeof(detalle), "REG_REQ de %s -> ERROR(tabla_llena)", msg->from);
                log_evento("ERROR", ip, puerto, detalle);
                break;
            }
            n->registrado = 1;
            strncpy(n->ip, ip, sizeof(n->ip) - 1);
            n->puerto = puerto;
            n->ultima_actividad = time(NULL);

            nmp_send(fd, TYPE_REG_ACK, msg->id, "servidor", "ok");
            snprintf(detalle, sizeof(detalle), "REG_REQ de %s -> REG_ACK(ok)", msg->from);
            log_evento("INFO", ip, puerto, detalle);
            break;
        }

        case TYPE_EVENT_REQ: {
            nodo_t *n = buscar_nodo(msg->from);
            if (!n || !n->registrado) {
                /* Regla básica del protocolo: no se aceptan eventos de un
                 * nodo que nunca completó su registro. */
                nmp_send(fd, TYPE_ERROR, msg->id, "servidor", "nodo_no_registrado");
                snprintf(detalle, sizeof(detalle), "EVENT_REQ de %s -> ERROR(nodo_no_registrado)", msg->from);
                log_evento("ERROR", ip, puerto, detalle);
                break;
            }
            n->num_eventos++;
            n->ultima_actividad = time(NULL);

            nmp_send(fd, TYPE_EVENT_ACK, msg->id, "servidor", "ok");
            {
                char detalle_grande[NMP_MAX_PAYLOAD + NMP_MAX_LINE];
                snprintf(detalle_grande, sizeof(detalle_grande),
                         "EVENT_REQ de %s (%s) -> EVENT_ACK(ok)", msg->from, msg->payload);
                log_evento("INFO", ip, puerto, detalle_grande);
            }
            break;
        }

        case TYPE_AUTH_REQ: {
            /* PLACEHOLDER de Fase 2: se acepta cualquier autenticación.
             * La integración real contra LDAP (ldap_bind, ver Bloque 6 de
             * la wiki) queda para la Fase 3. */
            nmp_send(fd, TYPE_AUTH_ACK, msg->id, "servidor", "ok");
            snprintf(detalle, sizeof(detalle),
                     "AUTH_REQ de %s -> AUTH_ACK(ok) [placeholder, LDAP pendiente para Fase 3]", msg->from);
            log_evento("INFO", ip, puerto, detalle);
            break;
        }

        case TYPE_QUERY_REQ: {
            char resultado[512] = "";
            for (int i = 0; i < num_nodos; i++) {
                char linea[350];
                snprintf(linea, sizeof(linea), "%s:%s;", nodos[i].id,
                         nodos[i].ultima_telemetria[0] ? nodos[i].ultima_telemetria : "sin_datos");
                strncat(resultado, linea, sizeof(resultado) - strlen(resultado) - 1);
            }
            nmp_send(fd, TYPE_QUERY_RESP, msg->id, "servidor", resultado);
            snprintf(detalle, sizeof(detalle), "QUERY_REQ de %s -> QUERY_RESP", msg->from);
            log_evento("INFO", ip, puerto, detalle);
            break;
        }

        default: {
            nmp_send(fd, TYPE_ERROR, msg->id, "servidor", "tipo_de_mensaje_desconocido");
            snprintf(detalle, sizeof(detalle), "TYPE=%d desconocido de %s", msg->type, msg->from);
            log_evento("ERROR", ip, puerto, detalle);
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Manejo de telemetría por UDP: no responde nada (fire-and-forget), solo  */
/* actualiza la tabla de estado si el nodo ya está registrado.             */
/* ---------------------------------------------------------------------- */
static void manejar_telemetria_udp(const char *ip, int puerto, nmp_message_t *msg) {
    char detalle[NMP_MAX_PAYLOAD + NMP_MAX_LINE];
    nodo_t *n = buscar_nodo(msg->from);

    if (!n || !n->registrado) {
        snprintf(detalle, sizeof(detalle), "TELEMETRY de %s IGNORADA (nodo no registrado)", msg->from);
        log_evento("WARNING", ip, puerto, detalle);
        return;
    }

    strncpy(n->ultima_telemetria, msg->payload, sizeof(n->ultima_telemetria) - 1);
    n->ultima_actividad = time(NULL);

    snprintf(detalle, sizeof(detalle), "TELEMETRY de %s: %s", msg->from, msg->payload);
    log_evento("INFO", ip, puerto, detalle);
}

/* ---------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <puerto> <archivoDeLogs>\n", argv[0]);
        return 1;
    }

    int puerto = atoi(argv[1]);
    log_file = fopen(argv[2], "a");
    if (!log_file) {
        perror("No se pudo abrir el archivo de logs");
        return 1;
    }

    /* Evita que el proceso muera si un cliente cierra la conexión abruptamente
     * mientras el servidor intenta escribirle (control de excepciones, req. 11) */
    signal(SIGPIPE, SIG_IGN);

    /* --- Socket TCP --- */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in tcp_addr;
    memset(&tcp_addr, 0, sizeof(tcp_addr));
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    tcp_addr.sin_port = htons(puerto);

    if (bind(tcp_fd, (struct sockaddr *) &tcp_addr, sizeof(tcp_addr)) < 0) {
        perror("bind TCP");
        return 1;
    }
    if (listen(tcp_fd, 10) < 0) {
        perror("listen");
        return 1;
    }

    /* --- Socket UDP (mismo número de puerto, socket distinto) --- */
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = INADDR_ANY;
    udp_addr.sin_port = htons(puerto);

    if (bind(udp_fd, (struct sockaddr *) &udp_addr, sizeof(udp_addr)) < 0) {
        perror("bind UDP");
        return 1;
    }

    char detalle[128];
    snprintf(detalle, sizeof(detalle), "Servidor SMCD escuchando en el puerto %d (TCP y UDP)", puerto);
    log_evento("INFO", "0.0.0.0", puerto, detalle);

    int clientes[MAX_CLIENTES_TCP];
    for (int i = 0; i < MAX_CLIENTES_TCP; i++) clientes[i] = -1;

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tcp_fd, &readfds);
        FD_SET(udp_fd, &readfds);
        int maxfd = (tcp_fd > udp_fd) ? tcp_fd : udp_fd;

        for (int i = 0; i < MAX_CLIENTES_TCP; i++) {
            if (clientes[i] >= 0) {
                FD_SET(clientes[i], &readfds);
                if (clientes[i] > maxfd) maxfd = clientes[i];
            }
        }

        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        /* Nueva conexión TCP entrante */
        if (FD_ISSET(tcp_fd, &readfds)) {
            struct sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(cli_addr);
            int new_fd = accept(tcp_fd, (struct sockaddr *) &cli_addr, &cli_len);

            if (new_fd >= 0) {
                int slot = -1;
                for (int i = 0; i < MAX_CLIENTES_TCP; i++) {
                    if (clientes[i] < 0) { slot = i; break; }
                }
                if (slot == -1) {
                    close(new_fd); /* sin espacio disponible por ahora */
                } else {
                    clientes[slot] = new_fd;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cli_addr.sin_addr, ip, sizeof(ip));
                    log_evento("INFO", ip, ntohs(cli_addr.sin_port), "Nueva conexion TCP aceptada");
                }
            }
        }

        /* Datagrama UDP entrante (telemetría) */
        if (FD_ISSET(udp_fd, &readfds)) {
            char buffer[2048];
            struct sockaddr_in remitente;
            socklen_t remitente_len = sizeof(remitente);
            int n = recvfrom(udp_fd, buffer, sizeof(buffer) - 1, 0,
                              (struct sockaddr *) &remitente, &remitente_len);
            if (n > 0) {
                buffer[n] = '\0';
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &remitente.sin_addr, ip, sizeof(ip));
                int puerto_remitente = ntohs(remitente.sin_port);

                nmp_message_t msg;
                if (nmp_parse_buffer(buffer, n, &msg) == 0 && msg.type == TYPE_TELEMETRY) {
                    manejar_telemetria_udp(ip, puerto_remitente, &msg);
                } else {
                    log_evento("ERROR", ip, puerto_remitente, "Datagrama UDP con formato invalido");
                }
            }
        }

        /* Mensajes de clientes TCP ya conectados */
        for (int i = 0; i < MAX_CLIENTES_TCP; i++) {
            if (clientes[i] >= 0 && FD_ISSET(clientes[i], &readfds)) {
                struct sockaddr_in cli_addr;
                socklen_t cli_len = sizeof(cli_addr);
                getpeername(clientes[i], (struct sockaddr *) &cli_addr, &cli_len);
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli_addr.sin_addr, ip, sizeof(ip));
                int puerto_cli = ntohs(cli_addr.sin_port);

                nmp_message_t msg;
                if (nmp_recv(clientes[i], &msg) < 0) {
                    log_evento("INFO", ip, puerto_cli, "Conexion TCP cerrada");
                    close(clientes[i]);
                    clientes[i] = -1;
                } else {
                    manejar_mensaje_tcp(clientes[i], ip, puerto_cli, &msg);
                }
            }
        }
    }

    fclose(log_file);
    close(tcp_fd);
    close(udp_fd);
    return 0;
}
