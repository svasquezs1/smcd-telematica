#ifndef LOG_H
#define LOG_H

#include <stddef.h>

/* Abre (en modo append) el archivo de logs. Devuelve 0 si ok, -1 si falla. */
int  log_iniciar(const char *ruta);
void log_cerrar(void);

/* Escribe una línea en consola y en el archivo:
 *   [fecha hora] [NIVEL] [ip:puerto] mensaje
 * Es seguro llamarla desde varios hilos a la vez (usa un mutex). */
void log_evento(const char *nivel, const char *ip, int puerto, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* Copia 'src' a 'out' reemplazando caracteres de control por '?' (evita que
 * un cliente falsifique líneas de log enviando saltos de línea) y truncando
 * a 'outlen'-1 bytes. Además enmascara el valor de password=... */
void log_sanear(const char *src, char *out, size_t outlen);

#endif
