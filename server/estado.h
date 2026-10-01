#ifndef ESTADO_H
#define ESTADO_H

#include <stddef.h>

/*
 * Estado compartido de la infraestructura (tabla de nodos, historial y eventos).
 *
 * Todas las funciones de este módulo son seguras para llamarse desde varios
 * hilos a la vez: un único mutex interno protege toda la estructura.
 * Regla de oro (ver Bloque 4): los demás módulos NUNCA tocan estos datos
 * directamente, solo a través de esta API.
 */

#define MAX_NODOS        100
#define MAX_HIST         10    /* muestras históricas por nodo              */
#define MAX_EVENTOS      50    /* eventos recientes que se conservan        */
#define MAX_IDS_EVENTO   16    /* ids de EVENT_REQ recordados (duplicados)  */
#define MAX_DATOS        256   /* tamaño máximo de una muestra/evento       */

/* Códigos de retorno */
#define EST_OK              0
#define EST_DUPLICADO       1    /* mensaje repetido o atrasado: se descarta  */
#define EST_NO_REGISTRADO  -1
#define EST_LLENO          -2
#define EST_ORIGEN_INVALIDO -3   /* la IP del datagrama no es la del nodo    */

/* Registra (o re-registra) un nodo. 'sesion' recibe el id de la sesión TCP
 * vigente; 'reemplazo' vale 1 si el nodo ya estaba conectado (reconexión). */
int  estado_registrar_nodo(const char *id, const char *tipo, const char *ip,
                           int puerto, unsigned long *sesion, int *reemplazo);

/* Marca el nodo como desconectado, solo si 'sesion' sigue siendo la vigente. */
void estado_nodo_desconectado(const char *id, unsigned long sesion);

/* Guarda una muestra de telemetría. 'recuperado' vale 1 si el nodo estaba
 * INACTIVO y vuelve a reportar. */
int  estado_telemetria(const char *id, int msg_id, const char *datos,
                       const char *ip_origen, int *recuperado);

/* Guarda un evento crítico enviado por un nodo (detecta duplicados por id). */
int  estado_evento(const char *id, int msg_id, const char *datos);

/* Revisa los nodos ACTIVOS: los que llevan más de 'timeout_s' segundos sin
 * reportar pasan a INACTIVO y se genera un evento. La llama el hilo monitor. */
void estado_revisar_inactividad(int timeout_s);

/* Construcción de respuestas de consulta. Escriben en 'out' (máx. 'n' bytes,
 * siempre terminado en '\0') y devuelven el número de registros incluidos. */
int  estado_listar(char *out, size_t n);
int  estado_historial(const char *id, int max, char *out, size_t n); /* -1 si el nodo no existe */
int  estado_eventos(char *out, size_t n);

#endif
