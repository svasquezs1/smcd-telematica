#ifndef PROTOCOLO_H
#define PROTOCOLO_H

#include <sys/socket.h>

#define NMP_MAX_PAYLOAD 1024
#define NMP_MAX_FROM 64
#define NMP_MAX_LINE 256

/* Tipos de mensaje NMP — deben coincidir exactamente con los definidos
 * en la especificación de la wiki y en common/protocolo.py */
#define TYPE_REG_REQ     1
#define TYPE_REG_ACK     2
#define TYPE_TELEMETRY   3
#define TYPE_EVENT_REQ   4
#define TYPE_EVENT_ACK   5
#define TYPE_AUTH_REQ    6
#define TYPE_AUTH_ACK    7
#define TYPE_QUERY_REQ   8
#define TYPE_QUERY_RESP  9
#define TYPE_ERROR       10

typedef struct {
    int  type;
    int  id;
    char from[NMP_MAX_FROM];
    int  len;
    char payload[NMP_MAX_PAYLOAD];
} nmp_message_t;

/* Lee un mensaje NMP completo (cabecera + payload) desde un socket TCP,
 * respetando el framing definido por el campo LEN (ver Bloque 3 / wiki).
 * Retorna 0 si tuvo éxito, -1 si la conexión se cerró o el mensaje es inválido. */
int nmp_recv(int sockfd, nmp_message_t *msg);

/* Construye y envía un mensaje NMP por un socket TCP. */
int nmp_send(int sockfd, int type, int id, const char *from, const char *payload);

/* Parsea un mensaje NMP ya recibido completo en un buffer (usado para UDP,
 * donde recvfrom() entrega el datagrama completo de una sola vez). */
int nmp_parse_buffer(const char *buffer, int buffer_len, nmp_message_t *msg);

#endif
