/*
 * Módulo de logging del servidor.
 * Requisito del enunciado: mostrar en consola Y guardar en archivo las
 * peticiones y respuestas, identificando al cliente por IP:puerto de origen.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "log.h"

static FILE *g_log = NULL;
static pthread_mutex_t g_log_mtx = PTHREAD_MUTEX_INITIALIZER;

int log_iniciar(const char *ruta) {
    g_log = fopen(ruta, "a");
    return g_log ? 0 : -1;
}

void log_cerrar(void) {
    pthread_mutex_lock(&g_log_mtx);
    if (g_log) { fclose(g_log); g_log = NULL; }
    pthread_mutex_unlock(&g_log_mtx);
}

void log_evento(const char *nivel, const char *ip, int puerto, const char *fmt, ...) {
    char mensaje[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(mensaje, sizeof(mensaje), fmt, ap);
    va_end(ap);

    time_t ahora = time(NULL);
    struct tm tm_local;
    localtime_r(&ahora, &tm_local);
    char fecha[32];
    strftime(fecha, sizeof(fecha), "%Y-%m-%d %H:%M:%S", &tm_local);

    pthread_mutex_lock(&g_log_mtx);
    printf("[%s] [%s] [%s:%d] %s\n", fecha, nivel, ip, puerto, mensaje);
    fflush(stdout);
    if (g_log) {
        fprintf(g_log, "[%s] [%s] [%s:%d] %s\n", fecha, nivel, ip, puerto, mensaje);
        fflush(g_log);
    }
    pthread_mutex_unlock(&g_log_mtx);
}

void log_sanear(const char *src, char *out, size_t outlen) {
    size_t o = 0;
    for (size_t i = 0; src[i] && o + 1 < outlen; i++) {
        unsigned char c = (unsigned char) src[i];
        out[o++] = (c < 0x20 || c == 0x7f) ? '?' : (char) c;
    }
    out[o] = '\0';

    /* Enmascara el valor de password=... (nunca se escribe una clave en el log) */
    char *p = strstr(out, "password=");
    if (p) {
        char *v = p + strlen("password=");
        while (*v && *v != ';') *v++ = '*';
    }
}
