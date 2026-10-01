/*
 * Autenticacion centralizada contra un servidor LDAP (requisito 6 del proyecto).
 *
 * El servidor SMCD NO guarda usuarios ni contrasenas: delega en el directorio.
 * Flujo (ver Bloque 6 y la pagina "Autenticacion" de la wiki):
 *   1. Se construye el DN del usuario:   uid=<usuario>,<base>
 *   2. Se intenta un BIND simple con ese DN y la contrasena recibida.
 *        - bind correcto  -> el usuario es quien dice ser (AUTENTICACION)
 *        - bind rechazado -> credenciales invalidas
 *   3. Ya autenticado, se lee el atributo employeeType de su propia entrada
 *      para obtener su PERFIL (admin / viewer)  (AUTORIZACION).
 *
 * Configuracion por variables de entorno (si no existen, valores por defecto):
 *   SMCD_LDAP_URI   ldap://localhost:389
 *   SMCD_LDAP_BASE  ou=people,dc=smcd,dc=local
 * Se usan NOMBRES de host (no IPs fijas): libldap los resuelve con getaddrinfo.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <ldap.h>
#include "auth.h"
#include "protocolo.h"   /* nmp_id_valido */
#include "log.h"

#define URI_POR_DEFECTO  "ldap://localhost:389"
#define BASE_POR_DEFECTO "ou=people,dc=smcd,dc=local"
#define TIMEOUT_LDAP_S   5

/* Lee el perfil del usuario (employeeType). Si no existe o falla la lectura,
 * se asigna el perfil de MENOR privilegio ("viewer"). */
static void leer_perfil(LDAP *ld, const char *dn, char *perfil, size_t perfil_len) {
    snprintf(perfil, perfil_len, "viewer");

    char *atributos[] = { "employeeType", NULL };
    struct timeval tv = { TIMEOUT_LDAP_S, 0 };
    LDAPMessage *res = NULL;

    int rc = ldap_search_ext_s(ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", atributos,
                               0, NULL, NULL, &tv, 1, &res);
    if (rc != LDAP_SUCCESS) {
        log_evento("WARNING", "-", 0, "LDAP: no se pudo leer el perfil de %s (%s): se usa 'viewer'",
                   dn, ldap_err2string(rc));
        if (res) ldap_msgfree(res);
        return;
    }
    LDAPMessage *entrada = ldap_first_entry(ld, res);
    if (entrada) {
        struct berval **vals = ldap_get_values_len(ld, entrada, "employeeType");
        if (vals && vals[0]) {
            char valor[32];
            size_t n = vals[0]->bv_len < sizeof(valor) - 1 ? vals[0]->bv_len : sizeof(valor) - 1;
            memcpy(valor, vals[0]->bv_val, n);
            valor[n] = '\0';
            if (strcasecmp(valor, "admin") == 0) snprintf(perfil, perfil_len, "admin");
        }
        if (vals) ldap_value_free_len(vals);
    }
    ldap_msgfree(res);
}

int auth_validar(const char *usuario, const char *password, char *perfil, size_t perfil_len) {
    /* 1. Defensas ANTES de tocar el directorio ------------------------------ */
    /* El usuario se inserta dentro de un DN: solo se permiten [A-Za-z0-9._-]
     * para impedir inyeccion de componentes de DN (por ejemplo "x,ou=admins"). */
    if (!nmp_id_valido(usuario)) return AUTH_CREDENCIALES_INVALIDAS;
    /* Un bind con contrasena vacia es un "unauthenticated bind": muchos
     * servidores LDAP lo aceptan como exito (anonimo). Se rechaza siempre. */
    if (password[0] == '\0') return AUTH_CREDENCIALES_INVALIDAS;

    const char *uri  = getenv("SMCD_LDAP_URI");
    const char *base = getenv("SMCD_LDAP_BASE");
    if (!uri  || !*uri)  uri  = URI_POR_DEFECTO;
    if (!base || !*base) base = BASE_POR_DEFECTO;

    /* 2. Conexion al directorio --------------------------------------------- */
    LDAP *ld = NULL;
    int rc = ldap_initialize(&ld, uri);
    if (rc != LDAP_SUCCESS) {
        log_evento("ERROR", "-", 0, "LDAP: URI invalida '%s' (%s)", uri, ldap_err2string(rc));
        return AUTH_SERVICIO_NO_DISPONIBLE;
    }
    int version = LDAP_VERSION3;
    struct timeval tv = { TIMEOUT_LDAP_S, 0 };
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);   /* conectar: maximo 5 s */
    ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv);           /* operaciones: maximo 5 s */

    /* 3. BIND con las credenciales del usuario ------------------------------ */
    char dn[256];
    snprintf(dn, sizeof(dn), "uid=%s,%s", usuario, base);

    struct berval cred;
    cred.bv_val = (char *) password;
    cred.bv_len = strlen(password);
    rc = ldap_sasl_bind_s(ld, dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);

    int resultado;
    if (rc == LDAP_SUCCESS) {
        leer_perfil(ld, dn, perfil, perfil_len);
        resultado = AUTH_OK;
    } else if (rc == LDAP_INVALID_CREDENTIALS || rc == LDAP_NO_SUCH_OBJECT ||
               rc == LDAP_INAPPROPRIATE_AUTH || rc == LDAP_CONSTRAINT_VIOLATION ||
               rc == LDAP_INVALID_DN_SYNTAX) {
        /* Usuario inexistente y clave incorrecta se tratan IGUAL: asi un atacante
         * no puede averiguar que usuarios existen (enumeracion de usuarios). */
        resultado = AUTH_CREDENCIALES_INVALIDAS;
    } else {
        /* Servidor caido, red, timeout, nombre no resuelto... */
        log_evento("ERROR", "-", 0, "LDAP: no se pudo autenticar contra %s (%s)", uri, ldap_err2string(rc));
        resultado = AUTH_SERVICIO_NO_DISPONIBLE;
    }

    ldap_unbind_ext_s(ld, NULL, NULL);
    return resultado;
}
