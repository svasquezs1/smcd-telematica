#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "protocolo.h"

/* Lee del socket byte por byte hasta encontrar '\n' (no incluido en el resultado).
 * Es una implementación simple, suficiente para el tamaño de mensajes de este
 * proyecto — ver Bloque 3 de la wiki para la explicación del problema de framing. */
static int recv_line(int sockfd, char *buf, int maxlen) {
    int i = 0;
    char c;
    while (i < maxlen - 1) {
        int n = recv(sockfd, &c, 1, 0);
        if (n <= 0) return -1; /* conexión cerrada o error */
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

/* Lee exactamente 'len' bytes del socket, acumulando en un bucle porque un
 * solo recv() no garantiza traer todo el payload de una vez (TCP es un
 * flujo de bytes, no mensajes delimitados). */
static int recv_exact(int sockfd, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sockfd, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return 0;
}

static int send_all(int sockfd, const char *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = send(sockfd, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return 0;
}

int nmp_recv(int sockfd, nmp_message_t *msg) {
    char line[NMP_MAX_LINE];

    /* Primera línea "NMP/1.0": la leemos y descartamos */
    if (recv_line(sockfd, line, sizeof(line)) < 0) return -1;

    memset(msg, 0, sizeof(nmp_message_t));
    int got_type = 0, got_id = 0, got_from = 0, got_len = 0;

    while (1) {
        if (recv_line(sockfd, line, sizeof(line)) < 0) return -1;
        if (line[0] == '\0') break; /* línea en blanco: fin de la cabecera */

        if (sscanf(line, "TYPE:%d", &msg->type) == 1) { got_type = 1; continue; }
        if (sscanf(line, "ID:%d", &msg->id) == 1) { got_id = 1; continue; }
        if (sscanf(line, "FROM:%63s", msg->from) == 1) { got_from = 1; continue; }
        if (sscanf(line, "LEN:%d", &msg->len) == 1) { got_len = 1; continue; }
        /* Cualquier otra línea de cabecera se ignora (tolerante a campos
         * desconocidos, pero exige los 4 campos obligatorios). */
    }

    if (!got_type || !got_id || !got_from || !got_len) return -1;
    if (msg->len < 0 || msg->len >= NMP_MAX_PAYLOAD) return -1;

    if (msg->len > 0) {
        if (recv_exact(sockfd, msg->payload, msg->len) < 0) return -1;
    }
    msg->payload[msg->len] = '\0';

    return 0;
}

int nmp_send(int sockfd, int type, int id, const char *from, const char *payload) {
    char msg[NMP_MAX_PAYLOAD + NMP_MAX_LINE];
    int payload_len = payload ? (int) strlen(payload) : 0;

    int n = snprintf(msg, sizeof(msg),
        "NMP/1.0\nTYPE:%d\nID:%d\nFROM:%s\nLEN:%d\n\n%s",
        type, id, from, payload_len, payload ? payload : "");

    if (n < 0 || n >= (int) sizeof(msg)) return -1;
    return send_all(sockfd, msg, n);
}

int nmp_parse_buffer(const char *buffer, int buffer_len, nmp_message_t *msg) {
    /* Busca la línea en blanco que separa la cabecera del payload */
    const char *sep = strstr(buffer, "\n\n");
    if (!sep) return -1;

    int header_len = (int)(sep - buffer);
    char header[NMP_MAX_LINE * 5];
    if (header_len >= (int) sizeof(header)) return -1;
    memcpy(header, buffer, header_len);
    header[header_len] = '\0';

    memset(msg, 0, sizeof(nmp_message_t));
    int got_type = 0, got_id = 0, got_from = 0, got_len = 0;

    char *line = strtok(header, "\n");
    while (line != NULL) {
        if (sscanf(line, "TYPE:%d", &msg->type) == 1) got_type = 1;
        else if (sscanf(line, "ID:%d", &msg->id) == 1) got_id = 1;
        else if (sscanf(line, "FROM:%63s", msg->from) == 1) got_from = 1;
        else if (sscanf(line, "LEN:%d", &msg->len) == 1) got_len = 1;
        line = strtok(NULL, "\n");
    }

    if (!got_type || !got_id || !got_from || !got_len) return -1;
    if (msg->len < 0 || msg->len >= NMP_MAX_PAYLOAD) return -1;

    const char *payload_start = sep + 2;
    int available = buffer_len - (int)(payload_start - buffer);
    if (available < msg->len) return -1;

    memcpy(msg->payload, payload_start, msg->len);
    msg->payload[msg->len] = '\0';

    return 0;
}
