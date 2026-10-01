#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

/* Resultado de validar unas credenciales */
#define AUTH_OK                    0
#define AUTH_CREDENCIALES_INVALIDAS 1   /* usuario/clave incorrectos           */
#define AUTH_SERVICIO_NO_DISPONIBLE -1  /* no se pudo hablar con el directorio */

/* Valida usuario y contraseña contra el servicio de autenticación centralizada.
 * Si es correcto, copia el PERFIL del usuario ("admin" o "viewer") en 'perfil'.
 * Es seguro llamarla desde varios hilos a la vez. */
int auth_validar(const char *usuario, const char *password, char *perfil, size_t perfil_len);

#endif
