/*
 * Capa de protocolo NMP (Node Monitoring Protocol) — lado servidor, en C.
 *
 * Responsabilidades de este módulo:
 *   - Leer/escribir mensajes NMP sobre sockets TCP (framing con LEN).
 *   - Parsear datagramas UDP completos.
 *   - Validar ESTRICTAMENTE el formato (versión, campos obligatorios, LEN,
 *     caracteres permitidos) para que un mensaje malicioso o corrupto nunca
 *     llegue a la lógica del servidor.
 *   - Utilidades para leer los campos clave=valor del payload.
 *
 * Todas las funciones son seguras para usarse desde varios hilos a la vez
 * (no usan variables globales ni strtok).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include "protocolo.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define NMP_VERSION_LINE "NMP/1.0"

/* Bits para comprobar que llegaron los 4 campos obligatorios */
#define F_TYPE 0x1
#define F_ID   0x2
#define F_FROM 0x4
#define F_LEN  0x8
#define F_ALL  (F_TYPE | F_ID | F_FROM | F_LEN)

/* ---------------------------------------------------------------------- */
/* Utilidades internas de lectura                                         */
/* ---------------------------------------------------------------------- */

/* Lee 1 byte. Devuelve 1 (ok), 0 (cerrada), -1 (error) o -2 (timeout). */
static int recv_byte(int fd, char *c) {
    for (;;) {
        ssize_t n = recv(fd, c, 1, 0);
        if (n == 1) return 1;
        if (n == 0) return 0;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -2;
        return -1;
    }
}

/* Lee una línea (sin el '\n' ni un posible '\r' final).
 * 'primera' = 1 si es la primera línea del mensaje: en ese caso un timeout
 * sin haber recibido ningún byte se interpreta como "conexión inactiva"
 * (NMP_ERR_TIMEOUT) y no como un mensaje incompleto. */
static int recv_line(int fd, char *buf, int maxlen, int primera) {
    int i = 0;
    for (;;) {
        char c;
        int r = recv_byte(fd, &c);
        if (r == 0 || r == -1) return NMP_ERR_CERRADA;
        if (r == -2) return (primera && i == 0) ? NMP_ERR_TIMEOUT : NMP_ERR_FORMATO;
        if (c == '\n') break;
        if (i >= maxlen - 1) return NMP_ERR_FORMATO;   /* línea demasiado larga */
        buf[i++] = c;
    }
    if (i > 0 && buf[i - 1] == '\r') i--;   /* tolera CRLF */
    buf[i] = '\0';
    return i;
}

/* Lee exactamente len bytes acumulando en un bucle (TCP es un flujo). */
static int recv_exact(int fd, char *buf, int len) {
    int total = 0;
    while (total < len) {
        ssize_t n = recv(fd, buf + total, (size_t)(len - total), 0);
        if (n > 0) { total += (int)n; continue; }
        if (n == 0) return NMP_ERR_CERRADA;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return NMP_ERR_FORMATO; /* payload incompleto */
        return NMP_ERR_CERRADA;
    }
    return NMP_OK;
}

static int send_all(int fd, const char *buf, int len) {
    int total = 0;
    while (total < len) {
        ssize_t n = send(fd, buf + total, (size_t)(len - total), MSG_NOSIGNAL);
        if (n > 0) { total += (int)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return NMP_ERR_CERRADA;
    }
    return NMP_OK;
}

/* ---------------------------------------------------------------------- */
/* Validaciones                                                           */
/* ---------------------------------------------------------------------- */

int nmp_id_valido(const char *id) {
    size_t n = strlen(id);
    if (n == 0 || n >= NMP_MAX_FROM) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) id[i];
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-')) return 0;
    }
    return 1;
}

/* Entero decimal no negativo, sin espacios ni basura al final. */
static int parse_uint(const char *s, int *out) {
    if (!isdigit((unsigned char) s[0])) return -1;
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end != '\0' || v < 0 || v > INT_MAX) return -1;
    *out = (int) v;
    return 0;
}

/* Interpreta una línea de cabecera. Devuelve 0 si es válida (conocida o una
 * clave desconocida, que se ignora) y -1 si una clave conocida trae un valor
 * inválido. */
static int parse_header_line(const char *line, nmp_message_t *msg, unsigned *seen) {
    if (strncmp(line, "TYPE:", 5) == 0) {
        if (parse_uint(line + 5, &msg->type) < 0) return -1;
        *seen |= F_TYPE;
    } else if (strncmp(line, "ID:", 3) == 0) {
        if (parse_uint(line + 3, &msg->id) < 0) return -1;
        *seen |= F_ID;
    } else if (strncmp(line, "FROM:", 5) == 0) {
        if (!nmp_id_valido(line + 5)) return -1;
        strncpy(msg->from, line + 5, NMP_MAX_FROM - 1);
        msg->from[NMP_MAX_FROM - 1] = '\0';
        *seen |= F_FROM;
    } else if (strncmp(line, "LEN:", 4) == 0) {
        if (parse_uint(line + 4, &msg->len) < 0) return -1;
        *seen |= F_LEN;
    }
    /* Otras líneas: se ignoran (el protocolo tolera campos desconocidos). */
    return 0;
}

static int cabecera_completa(const nmp_message_t *msg, unsigned seen) {
    if ((seen & F_ALL) != F_ALL) return 0;
    if (msg->len < 0 || msg->len >= NMP_MAX_PAYLOAD) return 0;
    return 1;
}

/* ---------------------------------------------------------------------- */
/* Recepción TCP                                                          */
/* ---------------------------------------------------------------------- */
int nmp_recv(int fd, nmp_message_t *msg) {
    char line[NMP_MAX_LINE];
    memset(msg, 0, sizeof(*msg));

    int rc = recv_line(fd, line, sizeof(line), 1);
    if (rc < 0) return rc;
    if (strcmp(line, NMP_VERSION_LINE) != 0) return NMP_ERR_FORMATO;

    unsigned seen = 0;
    int nlines = 0;
    for (;;) {
        rc = recv_line(fd, line, sizeof(line), 0);
        if (rc < 0) return rc;
        if (line[0] == '\0') break;                       /* fin de la cabecera */
        if (++nlines > NMP_MAX_HDR_LINES) return NMP_ERR_FORMATO;
        if (parse_header_line(line, msg, &seen) < 0) return NMP_ERR_FORMATO;
    }

    if (!cabecera_completa(msg, seen)) return NMP_ERR_FORMATO;

    if (msg->len > 0) {
        rc = recv_exact(fd, msg->payload, msg->len);
        if (rc < 0) return rc;
        if (memchr(msg->payload, '\0', (size_t) msg->len)) return NMP_ERR_FORMATO;
    }
    msg->payload[msg->len] = '\0';
    return NMP_OK;
}

/* ---------------------------------------------------------------------- */
/* Envío TCP                                                              */
/* ---------------------------------------------------------------------- */
int nmp_send(int fd, int type, int id, const char *from, const char *payload) {
    char out[NMP_MAX_PAYLOAD + 512];
    int plen = payload ? (int) strlen(payload) : 0;
    if (plen >= NMP_MAX_PAYLOAD) return NMP_ERR_FORMATO;

    int n = snprintf(out, sizeof(out),
                     "NMP/1.0\nTYPE:%d\nID:%d\nFROM:%s\nLEN:%d\n\n%s",
                     type, id, from, plen, payload ? payload : "");
    if (n < 0 || n >= (int) sizeof(out)) return NMP_ERR_FORMATO;
    return send_all(fd, out, n);
}

/* ---------------------------------------------------------------------- */
/* Parseo de datagramas UDP (el datagrama llega completo de una vez)      */
/* ---------------------------------------------------------------------- */
int nmp_parse_buffer(const char *buf, int n, nmp_message_t *msg) {
    memset(msg, 0, sizeof(*msg));
    if (n <= 0) return NMP_ERR_FORMATO;

    /* Busca la línea en blanco ("\n\n") que separa cabecera y payload */
    int hdr_end = -1;
    for (int i = 0; i + 1 < n; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n') { hdr_end = i; break; }
    }
    if (hdr_end < 0) return NMP_ERR_FORMATO;

    unsigned seen = 0;
    int pos = 0, lineno = 0;
    for (;;) {
        int start = pos;
        while (pos < hdr_end && buf[pos] != '\n') pos++;
        int llen = pos - start;
        if (llen >= NMP_MAX_LINE) return NMP_ERR_FORMATO;

        char line[NMP_MAX_LINE];
        memcpy(line, buf + start, (size_t) llen);
        line[llen] = '\0';
        if (llen > 0 && line[llen - 1] == '\r') line[llen - 1] = '\0';

        if (lineno == 0) {
            if (strcmp(line, NMP_VERSION_LINE) != 0) return NMP_ERR_FORMATO;
        } else {
            if (lineno > NMP_MAX_HDR_LINES || line[0] == '\0') return NMP_ERR_FORMATO;
            if (parse_header_line(line, msg, &seen) < 0) return NMP_ERR_FORMATO;
        }
        lineno++;

        if (pos >= hdr_end) break;   /* era la última línea de la cabecera */
        pos++;                        /* saltar el '\n' */
    }

    if (!cabecera_completa(msg, seen)) return NMP_ERR_FORMATO;

    const char *payload = buf + hdr_end + 2;
    int disponible = n - (hdr_end + 2);
    if (disponible != msg->len) return NMP_ERR_FORMATO;   /* LEN inconsistente */
    if (memchr(payload, '\0', (size_t) msg->len)) return NMP_ERR_FORMATO;

    memcpy(msg->payload, payload, (size_t) msg->len);
    msg->payload[msg->len] = '\0';
    return NMP_OK;
}

/* ---------------------------------------------------------------------- */
/* Payload clave=valor                                                    */
/* ---------------------------------------------------------------------- */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodifica %XX. Devuelve 0 si ok, -1 si la secuencia es inválida,
 * contiene %00 o no cabe en 'out'. */
static int url_decode(const char *src, size_t len, char *out, size_t outlen) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        if (c == '%') {
            if (i + 2 >= len) return -1;          /* faltan los 2 dígitos hex */
            int h = hexval(src[i + 1]), l = hexval(src[i + 2]);
            if (h < 0 || l < 0) return -1;
            c = (char) (h * 16 + l);
            if (c == '\0') return -1;
            i += 2;
        }
        if (o + 1 >= outlen) return -1;
        out[o++] = c;
    }
    out[o] = '\0';
    return 0;
}

int nmp_get_field(const char *payload, const char *key, char *out, size_t outlen) {
    size_t klen = strlen(key);
    const char *p = payload;
    while (*p) {
        const char *fin = strchr(p, ';');
        if (!fin) fin = p + strlen(p);
        const char *eq = memchr(p, '=', (size_t) (fin - p));
        if (eq && (size_t) (eq - p) == klen && strncmp(p, key, klen) == 0) {
            return url_decode(eq + 1, (size_t) (fin - (eq + 1)), out, outlen);
        }
        p = *fin ? fin + 1 : fin;
    }
    return -1;
}

int nmp_payload_valido(const char *payload) {
    if (payload[0] == '\0') return 1;
    const char *p = payload;
    for (;;) {
        const char *fin = strchr(p, ';');
        if (!fin) fin = p + strlen(p);
        if (fin == p) return 0;                       /* segmento vacío */
        const char *eq = memchr(p, '=', (size_t) (fin - p));
        if (!eq || eq == p) return 0;                 /* sin '=' o clave vacía */
        for (const char *k = p; k < eq; k++) {        /* clave: [A-Za-z0-9_] */
            if (!(isalnum((unsigned char) *k) || *k == '_')) return 0;
        }
        for (const char *v = eq + 1; v < fin; v++) {  /* valor: sin control, %XX válido */
            unsigned char c = (unsigned char) *v;
            if (c < 0x20 || c == 0x7f) return 0;
            if (c == '%') {
                if (v + 2 >= fin) return 0;       /* faltan los 2 dígitos hex */
                if (hexval(v[1]) < 0 || hexval(v[2]) < 0) return 0;
                v += 2;
            }
        }
        if (*fin == '\0') break;
        p = fin + 1;
        if (*p == '\0') return 0;                     /* ';' final sin segmento */
    }
    return 1;
}

const char *nmp_type_name(int type) {
    switch (type) {
        case TYPE_REG_REQ:    return "REG_REQ";
        case TYPE_REG_ACK:    return "REG_ACK";
        case TYPE_TELEMETRY:  return "TELEMETRY";
        case TYPE_EVENT_REQ:  return "EVENT_REQ";
        case TYPE_EVENT_ACK:  return "EVENT_ACK";
        case TYPE_AUTH_REQ:   return "AUTH_REQ";
        case TYPE_AUTH_ACK:   return "AUTH_ACK";
        case TYPE_QUERY_REQ:  return "QUERY_REQ";
        case TYPE_QUERY_RESP: return "QUERY_RESP";
        case TYPE_ERROR:      return "ERROR";
        default:              return "DESCONOCIDO";
    }
}
