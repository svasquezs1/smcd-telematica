#ifndef PROTOCOLO_H
#define PROTOCOLO_H

#include <stddef.h>
#include <sys/socket.h>

/* ---------------------------------------------------------------------- */
/* Límites del protocolo NMP                                              */
/* ---------------------------------------------------------------------- */
#define NMP_MAX_PAYLOAD 8192   /* tamaño máximo del payload (bytes)       */
#define NMP_MAX_FROM    64     /* tamaño máximo del campo FROM            */
#define NMP_MAX_LINE    256    /* tamaño máximo de una línea de cabecera  */
#define NMP_MAX_HDR_LINES 16   /* máximo de líneas de cabecera aceptadas  */

/* Tipos de mensaje — deben coincidir con la especificación (wiki) y con
 * common/protocolo.py */
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

/* Códigos de retorno de las funciones de recepción/parseo */
#define NMP_OK             0
#define NMP_ERR_CERRADA   -1   /* el otro extremo cerró o falló la E/S      */
#define NMP_ERR_FORMATO   -2   /* mensaje mal formado (cabecera/LEN/etc.)    */
#define NMP_ERR_TIMEOUT   -3   /* expiró el temporizador sin recibir nada    */

typedef struct {
    int  type;
    int  id;
    char from[NMP_MAX_FROM];
    int  len;
    char payload[NMP_MAX_PAYLOAD];
} nmp_message_t;

/* Lee un mensaje NMP completo desde un socket TCP, respetando el framing
 * definido por LEN. El socket debe tener SO_RCVTIMEO configurado si se
 * quiere detectar inactividad (en ese caso devuelve NMP_ERR_TIMEOUT cuando
 * no llegó ni un byte del mensaje). */
int nmp_recv(int sockfd, nmp_message_t *msg);

/* Construye y envía un mensaje NMP por TCP. Devuelve NMP_OK o NMP_ERR_CERRADA. */
int nmp_send(int sockfd, int type, int id, const char *from, const char *payload);

/* Parsea un datagrama UDP completo ya recibido (recvfrom). Es estricto: el
 * tamaño del payload debe coincidir exactamente con LEN. */
int nmp_parse_buffer(const char *buffer, int buffer_len, nmp_message_t *msg);

/* ---------------------------------------------------------------------- */
/* Payloads: lista de pares clave=valor separados por ';'.                */
/* Los valores van codificados con %XX (ver especificación) para poder    */
/* llevar caracteres como ';', '=' o '%' sin ambigüedad.                  */
/* ---------------------------------------------------------------------- */

/* Busca 'key' en el payload y copia su valor DECODIFICADO en 'out'.
 * Devuelve 0 si la clave existe, -1 si no existe o el valor no cabe. */
int nmp_get_field(const char *payload, const char *key, char *out, size_t outlen);

/* Devuelve 1 si el payload es sintácticamente válido (todos los segmentos
 * son clave=valor con clave no vacía), 0 si no. Un payload vacío es válido. */
int nmp_payload_valido(const char *payload);

/* Nombre legible de un tipo de mensaje (para logs). */
const char *nmp_type_name(int type);

/* 1 si 'id' es un identificador válido de nodo/usuario: [A-Za-z0-9._-]{1,63} */
int nmp_id_valido(const char *id);

#endif
