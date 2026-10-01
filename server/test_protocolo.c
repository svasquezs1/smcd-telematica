/*
 * Pruebas unitarias de la capa de protocolo (protocolo.c).
 * Ejecutar con:  make test
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "protocolo.h"

static int fallos = 0, total = 0;
#define CHECK(desc, cond) do { total++; if (cond) printf("  [OK]   %s\n", desc); \
    else { printf("  [FALLO] %s\n", desc); fallos++; } } while (0)

/* Hilo que escribe un mensaje por un socket en trozos de 3 bytes con pausas:
 * simula que TCP entrega el mensaje fragmentado. */
static const char *g_trozos_msg;
static int g_trozos_fd;
static void *escribe_en_trozos(void *a) {
    (void) a;
    size_t n = strlen(g_trozos_msg);
    for (size_t i = 0; i < n; i += 3) {
        size_t k = (n - i < 3) ? n - i : 3;
        send(g_trozos_fd, g_trozos_msg + i, k, 0);
        usleep(2000);
    }
    return NULL;
}

int main(void) {
    nmp_message_t m;
    char out[64];

    printf("== nmp_parse_buffer (UDP) ==\n");
    const char *ok = "NMP/1.0\nTYPE:3\nID:7\nFROM:nodo-01\nLEN:11\n\ncpu=50;te=1";
    CHECK("mensaje valido",
          nmp_parse_buffer(ok, (int) strlen(ok), &m) == NMP_OK && m.type == 3 &&
          m.id == 7 && strcmp(m.from, "nodo-01") == 0 && strcmp(m.payload, "cpu=50;te=1") == 0);

    const char *len_mal = "NMP/1.0\nTYPE:3\nID:7\nFROM:nodo-01\nLEN:5\n\ncpu=50;te=1";
    CHECK("LEN inconsistente -> FORMATO", nmp_parse_buffer(len_mal, (int) strlen(len_mal), &m) == NMP_ERR_FORMATO);

    const char *sin_from = "NMP/1.0\nTYPE:3\nID:7\nLEN:0\n\n";
    CHECK("falta FROM -> FORMATO", nmp_parse_buffer(sin_from, (int) strlen(sin_from), &m) == NMP_ERR_FORMATO);

    const char *ver_mal = "HTTP/1.1\nTYPE:3\nID:7\nFROM:a\nLEN:0\n\n";
    CHECK("version incorrecta -> FORMATO", nmp_parse_buffer(ver_mal, (int) strlen(ver_mal), &m) == NMP_ERR_FORMATO);

    const char *from_mal = "NMP/1.0\nTYPE:3\nID:7\nFROM:no;valido\nLEN:0\n\n";
    CHECK("FROM con caracteres invalidos -> FORMATO", nmp_parse_buffer(from_mal, (int) strlen(from_mal), &m) == NMP_ERR_FORMATO);

    const char *type_mal = "NMP/1.0\nTYPE:abc\nID:7\nFROM:a\nLEN:0\n\n";
    CHECK("TYPE no numerico -> FORMATO", nmp_parse_buffer(type_mal, (int) strlen(type_mal), &m) == NMP_ERR_FORMATO);

    const char *sin_blanco = "NMP/1.0\nTYPE:3\nID:7\nFROM:a\nLEN:0\n";
    CHECK("sin linea en blanco -> FORMATO", nmp_parse_buffer(sin_blanco, (int) strlen(sin_blanco), &m) == NMP_ERR_FORMATO);

    CHECK("datagrama vacio -> FORMATO", nmp_parse_buffer("", 0, &m) == NMP_ERR_FORMATO);

    printf("== payload clave=valor ==\n");
    CHECK("get_field simple", nmp_get_field("a=1;b=hola", "b", out, sizeof(out)) == 0 && strcmp(out, "hola") == 0);
    CHECK("get_field decodifica %XX",
          nmp_get_field("password=a%3Bb%3Dc%25", "password", out, sizeof(out)) == 0 && strcmp(out, "a;b=c%") == 0);
    CHECK("get_field clave inexistente", nmp_get_field("a=1", "z", out, sizeof(out)) == -1);
    CHECK("get_field no confunde prefijos", nmp_get_field("usuario2=x", "usuario", out, sizeof(out)) == -1);
    CHECK("get_field valor no cabe -> -1", nmp_get_field("a=0123456789", "a", out, 4) == -1);
    CHECK("get_field %00 rechazado", nmp_get_field("a=x%00y", "a", out, sizeof(out)) == -1);
    CHECK("get_field %ZZ rechazado", nmp_get_field("a=%ZZ", "a", out, sizeof(out)) == -1);
    CHECK("get_field % truncado rechazado", nmp_get_field("a=abc%4", "a", out, sizeof(out)) == -1);
    CHECK("payload_valido: normal", nmp_payload_valido("cpu=50.5;temp=60") == 1);
    CHECK("payload_valido: vacio", nmp_payload_valido("") == 1);
    CHECK("payload_valido: sin '='", nmp_payload_valido("cpu50") == 0);
    CHECK("payload_valido: clave vacia", nmp_payload_valido("=5") == 0);
    CHECK("payload_valido: segmento vacio", nmp_payload_valido("a=1;;b=2") == 0);
    CHECK("payload_valido: ';' final", nmp_payload_valido("a=1;") == 0);
    CHECK("payload_valido: salto de linea", nmp_payload_valido("a=1\nb=2") == 0);
    CHECK("payload_valido: %XX invalido", nmp_payload_valido("a=%G1") == 0);
    CHECK("id_valido: normal", nmp_id_valido("nodo-iot_01.a") == 1);
    CHECK("id_valido: espacio", nmp_id_valido("nodo 1") == 0);
    CHECK("id_valido: vacio", nmp_id_valido("") == 0);

    printf("== nmp_recv / nmp_send por TCP (socketpair) ==\n");
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    CHECK("send+recv ida y vuelta",
          nmp_send(sv[0], TYPE_REG_REQ, 42, "nodo-9", "tipo=iot") == NMP_OK &&
          nmp_recv(sv[1], &m) == NMP_OK && m.type == TYPE_REG_REQ && m.id == 42 &&
          strcmp(m.payload, "tipo=iot") == 0);

    /* Framing: dos mensajes pegados en un solo write deben leerse por separado */
    const char *dos = "NMP/1.0\nTYPE:4\nID:1\nFROM:a\nLEN:3\n\nx=1"
                      "NMP/1.0\nTYPE:4\nID:2\nFROM:a\nLEN:3\n\ny=2";
    send(sv[0], dos, strlen(dos), 0);
    CHECK("dos mensajes pegados: primero", nmp_recv(sv[1], &m) == NMP_OK && m.id == 1 && strcmp(m.payload, "x=1") == 0);
    CHECK("dos mensajes pegados: segundo", nmp_recv(sv[1], &m) == NMP_OK && m.id == 2 && strcmp(m.payload, "y=2") == 0);

    /* Framing: un mensaje fragmentado en trozos de 3 bytes */
    g_trozos_msg = "NMP/1.0\nTYPE:8\nID:5\nFROM:admin1\nLEN:14\n\nconsulta=estad";
    g_trozos_fd = sv[0];
    pthread_t th;
    pthread_create(&th, NULL, escribe_en_trozos, NULL);
    CHECK("mensaje fragmentado en trozos de 3 bytes",
          nmp_recv(sv[1], &m) == NMP_OK && m.id == 5 && strcmp(m.payload, "consulta=estad") == 0);
    pthread_join(th, NULL);

    /* Mensaje malformado por TCP */
    const char *basura = "HOLA MUNDO\n\n";
    send(sv[0], basura, strlen(basura), 0);
    CHECK("basura por TCP -> FORMATO", nmp_recv(sv[1], &m) == NMP_ERR_FORMATO);

    /* Tras un error de FORMATO el flujo TCP queda desincronizado (quedan bytes
     * sin leer); por eso el servidor cierra la conexion. Aqui usamos un
     * socketpair nuevo para la siguiente prueba. */
    close(sv[0]); close(sv[1]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    /* Payload incompleto + cierre */
    const char *trunc = "NMP/1.0\nTYPE:4\nID:1\nFROM:a\nLEN:50\n\ncorto";
    send(sv[0], trunc, strlen(trunc), 0);
    close(sv[0]);
    CHECK("payload incompleto y cierre -> CERRADA", nmp_recv(sv[1], &m) == NMP_ERR_CERRADA);
    close(sv[1]);

    /* Timeout sin datos */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct timeval tv = { 0, 200000 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    CHECK("sin datos -> TIMEOUT", nmp_recv(sv[1], &m) == NMP_ERR_TIMEOUT);
    close(sv[0]); close(sv[1]);

    printf("\nResultado: %d/%d pruebas OK\n", total - fallos, total);
    return fallos ? 1 : 0;
}
