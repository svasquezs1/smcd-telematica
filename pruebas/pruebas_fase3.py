#!/usr/bin/env python3
"""
Suite de pruebas de la Fase 3 del sistema SMCD.

Verifica contra un servidor YA EN EJECUCION (y con LDAP funcionando) cada
situacion que pide el enunciado: mensajes con formato incorrecto, parametros
invalidos, desconexiones, nodos desconocidos, temporizadores, duplicados,
autenticacion/perfiles y concurrencia.

Uso:
    python3 pruebas_fase3.py <host> <puerto> [opciones]

Opciones utiles:
    --timeout-nodo N   valor de SMCD_TIMEOUT_NODO con el que arranco el servidor (15)
    --rapido           omite las pruebas que esperan 10 s o mas
    --solo TEXTO       ejecuta solo las pruebas cuyo nombre contenga TEXTO
    --max-conexiones N activa la prueba del limite de conexiones (el servidor debe
                       haberse arrancado con SMCD_MAX_CONEXIONES=N)
    --ldap-caido       activa la prueba "LDAP no disponible" (detenga slapd antes)
"""
import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from protocolo import *  # noqa: E402,F401,F403

# ---------------------------------------------------------------------------
# Infraestructura minima de pruebas
# ---------------------------------------------------------------------------
PRUEBAS = []          # (nombre, funcion, tipo) tipo: "normal" | "lenta" | "limite" | "ldap"
CTX = argparse.Namespace()


class Fallo(AssertionError):
    pass


class ErrorServidor(Exception):
    def __init__(self, codigo, detalle=""):
        super().__init__(f"{codigo}: {detalle}")
        self.codigo = codigo


def prueba(nombre, tipo="normal"):
    def deco(f):
        PRUEBAS.append((nombre, f, tipo))
        return f
    return deco


def verificar(cond, mensaje):
    if not cond:
        raise Fallo(mensaje)


def esperar(cond, timeout=4.0, paso=0.1):
    fin = time.time() + timeout
    while time.time() < fin:
        r = cond()
        if r:
            return r
        time.sleep(paso)
    return cond()


def conectar(timeout=5):
    destino = resolver(CTX.host, CTX.puerto)
    verificar(destino is not None, f"no se pudo resolver {CTX.host}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(destino)
    return s


def pedir(s, tipo, id_msg, origen, payload=""):
    enviar_mensaje(s, tipo, id_msg, origen, payload)
    return recibir_mensaje(s)


def es_error(resp, codigo=None):
    if resp["tipo"] != TYPE_ERROR:
        return False
    return codigo is None or parsear_payload(resp["payload"]).get("codigo") == codigo


def conexion_cerrada(s, espera=3):
    """True si el servidor cerro la conexion (recv devuelve b'' o reset)."""
    s.settimeout(espera)
    try:
        return s.recv(1) == b""
    except (ConnectionError, OSError):
        return True


class Sesion:
    """Cliente de administracion autenticado."""
    def __init__(self, usuario, password):
        self.s = conectar()
        self.usuario = usuario
        self.n = 0
        self.resp_auth = self.pedir(TYPE_AUTH_REQ,
                                    construir_payload({"usuario": usuario, "password": password}))
        campos = parsear_payload(self.resp_auth["payload"]) if self.resp_auth["tipo"] == TYPE_AUTH_ACK else {}
        self.ok = campos.get("resultado") == "ok"
        self.perfil = campos.get("perfil")
        self.token = campos.get("sesion")

    def pedir(self, tipo, payload):
        self.n += 1
        return pedir(self.s, tipo, self.n, self.usuario, payload)

    def consulta(self, **campos):
        r = self.pedir(TYPE_QUERY_REQ, construir_payload({"sesion": self.token, **campos}))
        if r["tipo"] == TYPE_ERROR:
            c = parsear_payload(r["payload"])
            raise ErrorServidor(c.get("codigo"), c.get("detalle"))
        return parsear_registros(r["payload"])

    def cerrar(self):
        try:
            self.s.close()
        except OSError:
            pass


def admin():
    s = Sesion(*CTX.admin)
    verificar(s.ok, f"no se pudo autenticar el admin: {s.resp_auth}")
    return s


class Nodo:
    """Nodo simulado minimo para las pruebas."""
    def __init__(self, id_nodo, tipo="iot"):
        self.id = id_nodo
        self.tipo = tipo
        self.n = 0
        self.tcp = None
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.destino = resolver(CTX.host, CTX.puerto, socket.SOCK_DGRAM)

    def _id(self):
        self.n += 1
        return self.n

    def registrar(self):
        self.tcp = conectar()
        self.n = 0
        r = pedir(self.tcp, TYPE_REG_REQ, self._id(), self.id, f"tipo={self.tipo}")
        verificar(r["tipo"] == TYPE_REG_ACK, f"registro rechazado: {r}")
        return r

    def telemetria(self, **metricas):
        enviar_datagrama(self.udp, self.destino, TYPE_TELEMETRY, self._id(), self.id,
                         construir_payload(metricas))

    def telemetria_con_id(self, id_msg, **metricas):
        enviar_datagrama(self.udp, self.destino, TYPE_TELEMETRY, id_msg, self.id,
                         construir_payload(metricas))

    def evento(self, id_msg=None, **campos):
        return pedir(self.tcp, TYPE_EVENT_REQ, id_msg if id_msg is not None else self._id(),
                     self.id, construir_payload(campos))

    def cerrar(self):
        for x in (self.tcp, self.udp):
            try:
                if x:
                    x.close()
            except OSError:
                pass


def datos_nodo(sesion, id_nodo):
    """(meta, datos) del nodo en la consulta 'estado', o None si no aparece."""
    _, regs = sesion.consulta(consulta="estado")
    for meta, datos in regs:
        if meta.get("nodo") == id_nodo:
            return meta, datos
    return None


def estado_nodo(sesion, id_nodo):
    r = datos_nodo(sesion, id_nodo)
    return r[0]["estado"] if r else None


# ===========================================================================
# A. FORMATO Y PARAMETROS INVALIDOS
# ===========================================================================
@prueba("A1 Basura por TCP -> ERROR FORMATO_INVALIDO y el servidor sigue vivo")
def _():
    s = conectar()
    s.sendall(b"HOLA MUNDO ESTO NO ES NMP\n\n")
    r = recibir_mensaje(s)
    verificar(es_error(r, "FORMATO_INVALIDO"), f"respuesta inesperada: {r}")
    verificar(conexion_cerrada(s), "el servidor debia cerrar la conexion tras el error de formato")
    a = admin(); a.cerrar()    # el servidor sigue atendiendo


@prueba("A2 Version de protocolo incorrecta -> FORMATO_INVALIDO")
def _():
    s = conectar()
    s.sendall(b"NMP/9.9\nTYPE:1\nID:1\nFROM:x\nLEN:0\n\n")
    verificar(es_error(recibir_mensaje(s), "FORMATO_INVALIDO"), "no rechazo la version")


@prueba("A3 Falta un campo obligatorio de la cabecera -> FORMATO_INVALIDO")
def _():
    s = conectar()
    s.sendall(b"NMP/1.0\nTYPE:1\nID:1\nLEN:0\n\n")    # sin FROM
    verificar(es_error(recibir_mensaje(s), "FORMATO_INVALIDO"), "no rechazo la cabecera incompleta")


@prueba("A4 FROM con caracteres no permitidos -> FORMATO_INVALIDO")
def _():
    s = conectar()
    s.sendall(b"NMP/1.0\nTYPE:1\nID:1\nFROM:no;valido\nLEN:0\n\n")
    verificar(es_error(recibir_mensaje(s), "FORMATO_INVALIDO"), "no rechazo FROM invalido")


@prueba("A5 LEN gigante (fuera de rango) -> FORMATO_INVALIDO")
def _():
    s = conectar()
    s.sendall(b"NMP/1.0\nTYPE:4\nID:1\nFROM:x\nLEN:99999999\n\n")
    verificar(es_error(recibir_mensaje(s), "FORMATO_INVALIDO"), "no rechazo el LEN fuera de rango")


@prueba("A6 LEN menor que el payload real -> el servidor detecta el desfase")
def _():
    s = conectar()
    # Declara LEN:3 pero envia "tipo=iot\n": el payload leido es "tip" (invalido) y
    # los bytes sobrantes ("o=iot\n") quedan como el inicio de un mensaje corrupto.
    s.sendall(b"NMP/1.0\nTYPE:1\nID:1\nFROM:desfase\nLEN:3\n\ntipo=iot\n")
    r1 = recibir_mensaje(s)
    verificar(es_error(r1, "PARAMETRO_INVALIDO"), f"primera respuesta inesperada: {r1}")
    r2 = recibir_mensaje(s)
    verificar(es_error(r2, "FORMATO_INVALIDO"), f"segunda respuesta inesperada: {r2}")


@prueba("A7 TYPE desconocido -> ERROR TIPO_DESCONOCIDO (la conexion sigue abierta)")
def _():
    s = conectar()
    r = pedir(s, 99, 1, "x", "")
    verificar(es_error(r, "TIPO_DESCONOCIDO"), f"respuesta: {r}")
    r = pedir(s, TYPE_REG_REQ, 2, "a7-nodo", "tipo=iot")    # y aun puede usarse
    verificar(r["tipo"] == TYPE_REG_ACK, "la conexion deberia seguir utilizable")


@prueba("A8 REG_REQ sin 'tipo' o con tipo invalido -> PARAMETRO_INVALIDO")
def _():
    s = conectar()
    verificar(es_error(pedir(s, TYPE_REG_REQ, 1, "a8", ""), "PARAMETRO_INVALIDO"), "REG sin tipo")
    verificar(es_error(pedir(s, TYPE_REG_REQ, 2, "a8", "tipo=marciano"), "PARAMETRO_INVALIDO"), "REG tipo invalido")


@prueba("A9 Payload sintacticamente invalido -> PARAMETRO_INVALIDO")
def _():
    s = conectar()
    verificar(es_error(pedir(s, TYPE_REG_REQ, 1, "a9", "esto-no-tiene-igual"), "PARAMETRO_INVALIDO"), "sin '='")
    verificar(es_error(pedir(s, TYPE_REG_REQ, 2, "a9", "a=1;;b=2"), "PARAMETRO_INVALIDO"), "segmento vacio")
    verificar(es_error(pedir(s, TYPE_REG_REQ, 3, "a9", "a=%ZZ"), "PARAMETRO_INVALIDO"), "%XX invalido")


@prueba("A10 Secuencia invalida: EVENT_REQ sin registrarse / QUERY_REQ sin autenticarse")
def _():
    s = conectar()
    verificar(es_error(pedir(s, TYPE_EVENT_REQ, 1, "a10", "tipo=falla"), "NO_REGISTRADO"), "EVENT sin REG")
    verificar(es_error(pedir(s, TYPE_QUERY_REQ, 2, "a10", "consulta=estado"), "NO_AUTENTICADO"), "QUERY sin AUTH")


@prueba("A11 El cliente envia mensajes que solo envia el servidor / TELEMETRY por TCP")
def _():
    s = conectar()
    verificar(es_error(pedir(s, TYPE_REG_ACK, 1, "a11", "resultado=ok"), "FUERA_DE_SECUENCIA"), "REG_ACK desde cliente")
    verificar(es_error(pedir(s, TYPE_TELEMETRY, 2, "a11", "cpu=1"), "FUERA_DE_SECUENCIA"), "TELEMETRY por TCP")


@prueba("A12 Demasiados errores seguidos -> el servidor cierra la conexion")
def _():
    s = conectar()
    for i in range(5):
        try:
            r = pedir(s, TYPE_QUERY_REQ, i + 1, "a12", "consulta=estado")
            verificar(es_error(r), "se esperaba ERROR")
        except ConnectionError:
            break
    verificar(conexion_cerrada(s), "el servidor debia cerrar tras 5 errores seguidos")


@prueba("A13 Conexion que no se identifica -> ERROR TIMEOUT y cierre (10 s)", "lenta")
def _():
    s = conectar(timeout=15)
    r = recibir_mensaje(s)    # el servidor habla primero cuando vence el temporizador
    verificar(es_error(r, "TIMEOUT"), f"respuesta: {r}")
    verificar(conexion_cerrada(s), "debia cerrar la conexion")


@prueba("A14 Datagramas UDP basura o con LEN incorrecto no afectan al servidor")
def _():
    destino = resolver(CTX.host, CTX.puerto, socket.SOCK_DGRAM)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for dato in (b"basura", b"", b"NMP/1.0\nTYPE:3\nID:1\nFROM:x\nLEN:50\n\ncorto", b"\x00\xff" * 100):
        u.sendto(dato, destino)
    time.sleep(0.3)
    a = admin(); a.consulta(consulta="estado"); a.cerrar()


# ===========================================================================
# B. NODOS: eventos, duplicados, telemetria, desconexion
# ===========================================================================
@prueba("B1 Registro, EVENT_REQ confirmado y evento visible para el admin")
def _():
    n = Nodo("t-evento")
    n.registrar()
    r = n.evento(tipo="umbral_superado", metrica="cpu", valor="97.2")
    verificar(r["tipo"] == TYPE_EVENT_ACK and parsear_payload(r["payload"]).get("resultado") == "ok", f"{r}")
    a = admin()
    _, evs = a.consulta(consulta="eventos")
    verificar(any(m.get("nodo") == "t-evento" and d.get("tipo") == "umbral_superado" for m, d in evs),
              "el evento no aparece en la bitacora")
    a.cerrar(); n.cerrar()


@prueba("B2 EVENT_REQ duplicado (reintento): se confirma de nuevo pero se guarda UNA vez")
def _():
    n = Nodo("t-dup-evento")
    n.registrar()
    marca = f"m{int(time.time()*1000)}"
    r1 = n.evento(id_msg=500, tipo="falla", marca=marca)
    r2 = n.evento(id_msg=500, tipo="falla", marca=marca)      # mismo ID: reintento
    verificar(parsear_payload(r1["payload"]).get("duplicado") is None, "el primero no es duplicado")
    verificar(parsear_payload(r2["payload"]).get("duplicado") == "1", f"el segundo debia ser duplicado: {r2}")
    a = admin()
    _, evs = a.consulta(consulta="eventos")
    veces = sum(1 for m, d in evs if d.get("marca") == marca)
    verificar(veces == 1, f"el evento se guardo {veces} veces (esperado 1)")
    a.cerrar(); n.cerrar()


@prueba("B3 EVENT_REQ con FROM distinto al nodo registrado -> IDENTIDAD_INVALIDA")
def _():
    n = Nodo("t-identidad")
    n.registrar()
    r = pedir(n.tcp, TYPE_EVENT_REQ, 50, "otro-nodo", "tipo=falla")
    verificar(es_error(r, "IDENTIDAD_INVALIDA"), f"respuesta: {r}")
    n.cerrar()


@prueba("B4 EVENT_REQ sin campo 'tipo' -> PARAMETRO_INVALIDO")
def _():
    n = Nodo("t-evento-malo")
    n.registrar()
    verificar(es_error(n.evento(severidad="alta"), "PARAMETRO_INVALIDO"), "evento sin tipo")
    n.cerrar()


@prueba("B5 REG_REQ repetido en la misma conexion -> FUERA_DE_SECUENCIA")
def _():
    n = Nodo("t-reg-doble")
    n.registrar()
    r = pedir(n.tcp, TYPE_REG_REQ, 9, n.id, "tipo=iot")
    verificar(es_error(r, "FUERA_DE_SECUENCIA"), f"respuesta: {r}")
    n.cerrar()


@prueba("B6 Telemetria de un nodo NO registrado (nodo desconocido) se ignora")
def _():
    n = Nodo("t-fantasma")           # nunca llama a registrar()
    n.telemetria(cpu="50")
    time.sleep(0.4)
    a = admin()
    verificar(datos_nodo(a, "t-fantasma") is None, "un nodo no registrado aparecio en el estado")
    a.cerrar(); n.cerrar()


@prueba("B7 Telemetria UDP repetida o desordenada: solo cuenta la primera version")
def _():
    n = Nodo("t-udp-orden")
    n.registrar()
    n.telemetria_con_id(10, valor="a10")
    n.telemetria_con_id(11, valor="a11")
    n.telemetria_con_id(11, valor="DUPLICADO")      # repetida
    n.telemetria_con_id(9, valor="ATRASADO")        # llego tarde
    n.telemetria_con_id(12, valor="a12")
    a = admin()
    esperar(lambda: (datos_nodo(a, "t-udp-orden") or ({}, {}))[1].get("valor") == "a12")
    _, regs = a.consulta(consulta="historial", nodo="t-udp-orden", n=10)
    valores = [d.get("valor") for _, d in regs]
    verificar(valores == ["a12", "a11", "a10"], f"historial inesperado: {valores}")
    a.cerrar(); n.cerrar()


@prueba("B8 Historial: se conservan las 10 ultimas muestras (el enunciado pide al menos 5)")
def _():
    n = Nodo("t-historial")
    n.registrar()
    for i in range(1, 13):
        n.telemetria(temp=40 + i, bateria=100 - i)
        time.sleep(0.02)
    a = admin()
    esperar(lambda: (datos_nodo(a, "t-historial") or ({}, {}))[1].get("temp") == "52")
    _, regs = a.consulta(consulta="historial", nodo="t-historial")
    verificar(len(regs) == 10, f"se esperaban 10 muestras y llegaron {len(regs)}")
    verificar(regs[0][1]["temp"] == "52", "la primera debe ser la mas reciente")
    verificar(regs[-1][1]["temp"] == "43", "la ultima debe ser la mas antigua conservada")
    _, cinco = a.consulta(consulta="historial", nodo="t-historial", n=5)
    verificar(len(cinco) == 5, "n=5 debe devolver 5 muestras")
    a.cerrar(); n.cerrar()


@prueba("B9 Desconexion abrupta de un nodo -> estado DESCONECTADO (el servidor sigue)")
def _():
    n = Nodo("t-caida")
    n.registrar()
    n.telemetria(cpu="10")
    a = admin()
    esperar(lambda: estado_nodo(a, "t-caida") == "ACTIVO")
    n.tcp.close()     # el nodo "se cae"
    verificar(esperar(lambda: estado_nodo(a, "t-caida") == "DESCONECTADO"),
              "el nodo no paso a DESCONECTADO")
    _, evs = a.consulta(consulta="eventos")
    verificar(any(m.get("nodo") == "t-caida" and d.get("tipo") == "nodo_desconectado" for m, d in evs),
              "falta el evento nodo_desconectado")
    a.cerrar(); n.cerrar()


@prueba("B10 Reconexion: el nodo vuelve a registrarse y conserva su historial")
def _():
    n = Nodo("t-reconecta")
    n.registrar()
    n.telemetria(marca="antes")
    a = admin()
    esperar(lambda: (datos_nodo(a, "t-reconecta") or ({}, {}))[1].get("marca") == "antes")
    n.tcp.close()
    esperar(lambda: estado_nodo(a, "t-reconecta") == "DESCONECTADO")
    n.registrar()
    verificar(esperar(lambda: estado_nodo(a, "t-reconecta") == "ACTIVO"), "no volvio a ACTIVO")
    n.telemetria(marca="despues")
    esperar(lambda: (datos_nodo(a, "t-reconecta") or ({}, {}))[1].get("marca") == "despues")
    _, regs = a.consulta(consulta="historial", nodo="t-reconecta")
    marcas = [d.get("marca") for _, d in regs]
    verificar(marcas[:2] == ["despues", "antes"], f"historial: {marcas}")
    a.cerrar(); n.cerrar()


@prueba("B11 Dos conexiones con el mismo id: la nueva reemplaza a la vieja sin marcarlo caido")
def _():
    viejo = Nodo("t-reemplazo")
    viejo.registrar()
    nuevo = Nodo("t-reemplazo")
    nuevo.registrar()
    viejo.tcp.close()                # al cerrar la sesion vieja NO debe marcarse desconectado
    time.sleep(0.6)
    a = admin()
    verificar(estado_nodo(a, "t-reemplazo") == "ACTIVO", "la sesion vieja no debia desconectar al nodo")
    a.cerrar(); viejo.cerrar(); nuevo.cerrar()


@prueba("B12 Nodo que deja de enviar telemetria pasa a INACTIVO y se recupera", "lenta")
def _():
    n = Nodo("t-inactivo")
    n.registrar()
    n.telemetria(cpu="5")
    a = admin()
    esperar(lambda: estado_nodo(a, "t-inactivo") == "ACTIVO")
    limite = CTX.timeout_nodo + 4
    verificar(esperar(lambda: estado_nodo(a, "t-inactivo") == "INACTIVO", timeout=limite, paso=0.5),
              f"el nodo no paso a INACTIVO en {limite} s")
    _, evs = a.consulta(consulta="eventos")
    verificar(any(m.get("nodo") == "t-inactivo" and d.get("tipo") == "nodo_inactivo" for m, d in evs),
              "falta el evento nodo_inactivo")
    n.telemetria(cpu="6")            # vuelve a reportar
    verificar(esperar(lambda: estado_nodo(a, "t-inactivo") == "ACTIVO"), "el nodo no se recupero")
    a.cerrar(); n.cerrar()


# ===========================================================================
# C. AUTENTICACION (LDAP) Y PERFILES
# ===========================================================================
@prueba("C1 Credenciales correctas: perfiles admin y viewer segun LDAP")
def _():
    a = Sesion(*CTX.admin)
    v = Sesion(*CTX.viewer)
    verificar(a.ok and a.perfil == "admin", f"admin: {a.resp_auth}")
    verificar(v.ok and v.perfil == "viewer", f"viewer: {v.resp_auth}")
    a.cerrar(); v.cerrar()


@prueba("C2 Clave incorrecta, usuario inexistente y clave vacia: mismo rechazo")
def _():
    motivos = set()
    for usuario, clave in ((CTX.admin[0], "clave-mala"), ("no-existe-xyz", "lo-que-sea"), (CTX.admin[0], "")):
        s = Sesion(usuario, clave)
        verificar(not s.ok, f"{usuario!r}/{clave!r} no debia autenticar")
        verificar(s.resp_auth["tipo"] == TYPE_AUTH_ACK, f"respuesta: {s.resp_auth}")
        motivos.add(parsear_payload(s.resp_auth["payload"]).get("motivo"))
        s.cerrar()
    verificar(motivos == {"credenciales_invalidas"}, f"motivos distintos (permite enumerar usuarios): {motivos}")


@prueba("C3 Tres intentos fallidos -> el servidor cierra la conexion")
def _():
    s = conectar()
    for i in range(3):
        r = pedir(s, TYPE_AUTH_REQ, i + 1, CTX.admin[0],
                  construir_payload({"usuario": CTX.admin[0], "password": f"mala{i}"}))
        verificar(r["tipo"] == TYPE_AUTH_ACK, f"respuesta: {r}")
    verificar(conexion_cerrada(s), "debia cerrar tras 3 intentos fallidos")


@prueba("C4 Perfil viewer: puede ver estado e historial, NO la bitacora de eventos")
def _():
    v = Sesion(*CTX.viewer)
    verificar(v.ok, "viewer no autentico")
    v.consulta(consulta="estado")
    try:
        v.consulta(consulta="eventos")
        raise Fallo("el viewer no deberia poder consultar eventos")
    except ErrorServidor as e:
        verificar(e.codigo == "ACCESO_DENEGADO", f"codigo: {e.codigo}")
    v.cerrar()


@prueba("C5 Token de sesion falso -> SESION_INVALIDA")
def _():
    a = admin()
    r = pedir(a.s, TYPE_QUERY_REQ, 99, a.usuario, "sesion=0000000000000000;consulta=estado")
    verificar(es_error(r, "SESION_INVALIDA"), f"respuesta: {r}")
    a.cerrar()


@prueba("C6 Clave con ';' '=' '%' no rompe el protocolo (se rechaza como credencial)")
def _():
    s = Sesion(CTX.admin[0], "a;b=c%d;usuario=otro")
    verificar(s.resp_auth["tipo"] == TYPE_AUTH_ACK and not s.ok, f"respuesta: {s.resp_auth}")
    s.cerrar()


@prueba("C7 Inyeccion de DN en el usuario ('admin1,ou=x') es rechazada")
def _():
    s = conectar()
    r = pedir(s, TYPE_AUTH_REQ, 1, CTX.admin[0],
              construir_payload({"usuario": CTX.admin[0] + ",ou=admins", "password": "x"}))
    verificar(es_error(r, "IDENTIDAD_INVALIDA"), f"respuesta: {r}")
    s.close()


@prueba("C8 Un cliente ya autenticado no puede volver a autenticarse (ni registrar nodos)")
def _():
    a = admin()
    r = a.pedir(TYPE_AUTH_REQ, construir_payload({"usuario": a.usuario, "password": CTX.admin[1]}))
    verificar(es_error(r, "FUERA_DE_SECUENCIA"), f"AUTH repetido: {r}")
    r = a.pedir(TYPE_REG_REQ, "tipo=iot")
    verificar(es_error(r, "FUERA_DE_SECUENCIA"), f"REG desde un cliente: {r}")
    a.cerrar()


@prueba("C9 Consulta de historial de un nodo inexistente -> NODO_DESCONOCIDO", )
def _():
    a = admin()
    try:
        a.consulta(consulta="historial", nodo="nodo-que-no-existe")
        raise Fallo("debia fallar")
    except ErrorServidor as e:
        verificar(e.codigo == "NODO_DESCONOCIDO", e.codigo)
    try:
        a.consulta(consulta="historial", nodo="x", n=99)
        raise Fallo("n=99 debia fallar")
    except ErrorServidor as e:
        verificar(e.codigo == "PARAMETRO_INVALIDO", e.codigo)
    a.cerrar()


@prueba("C10 LDAP no disponible -> ERROR SERVICIO_AUTH_NO_DISPONIBLE y el servidor sigue", "ldap")
def _():
    s = conectar(timeout=15)
    r = pedir(s, TYPE_AUTH_REQ, 1, CTX.admin[0],
              construir_payload({"usuario": CTX.admin[0], "password": CTX.admin[1]}))
    verificar(es_error(r, "SERVICIO_AUTH_NO_DISPONIBLE"), f"respuesta: {r}")
    # el servidor sigue atendiendo a los nodos aunque no haya LDAP
    n = Nodo("t-sin-ldap")
    n.registrar()
    n.cerrar()
    s.close()


# ===========================================================================
# D. CONCURRENCIA
# ===========================================================================
@prueba("D1 50 nodos conectados A LA VEZ (registro + telemetria + evento)")
def _():
    N = 50
    barrera = threading.Barrier(N + 1, timeout=30)
    errores = []

    def worker(i):
        nodo = Nodo(f"carga-{i:03d}")
        try:
            nodo.registrar()
            nodo.telemetria(temp=20 + i, bateria=90)
            r = nodo.evento(tipo="prueba_carga", indice=i)
            if r["tipo"] != TYPE_EVENT_ACK:
                errores.append(f"nodo {i}: {r}")
            barrera.wait()          # todos conectados simultaneamente
            barrera.wait()          # espera a que el hilo principal consulte
        except Exception as e:      # noqa: BLE001
            errores.append(f"nodo {i}: {e!r}")
            try:
                barrera.abort()
            except Exception:       # noqa: BLE001
                pass
        finally:
            nodo.cerrar()

    hilos = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for h in hilos:
        h.start()
    barrera.wait()
    a = admin()
    esperar(lambda: sum(1 for m, d in a.consulta(consulta="estado")[1]
                        if m["nodo"].startswith("carga-") and d.get("bateria") == "90") == N, timeout=6)
    _, regs = a.consulta(consulta="estado")
    activos = [m for m, d in regs if m["nodo"].startswith("carga-") and m["estado"] == "ACTIVO"]
    con_datos = [m for m, d in regs if m["nodo"].startswith("carga-") and d.get("bateria") == "90"]
    a.cerrar()
    barrera.wait()
    for h in hilos:
        h.join()
    verificar(not errores, f"errores en los nodos: {errores[:3]}")
    verificar(len(activos) == N, f"ACTIVOS={len(activos)} (esperado {N})")
    verificar(len(con_datos) == N, f"con telemetria={len(con_datos)} (esperado {N})")


@prueba("D2 20 clientes autenticandose y consultando A LA VEZ (LDAP concurrente)")
def _():
    N = 20
    resultados = []
    lock = threading.Lock()

    def worker(i):
        try:
            u, p = (CTX.admin if i % 2 == 0 else CTX.viewer)
            s = Sesion(u, p)
            ok = s.ok
            for _ in range(5):
                s.consulta(consulta="estado")
            s.cerrar()
        except Exception as e:      # noqa: BLE001
            ok = repr(e)
        with lock:
            resultados.append(ok)

    hilos = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    t0 = time.time()
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    malos = [r for r in resultados if r is not True]
    verificar(len(resultados) == N and not malos, f"fallos: {malos[:3]}")
    verificar(time.time() - t0 < 20, "tardo demasiado")


@prueba("D3 Un cliente que abre la conexion y no envia nada NO bloquea a los demas")
def _():
    colgados = [conectar() for _ in range(10)]     # 10 conexiones mudas
    t0 = time.time()
    a = admin()
    a.consulta(consulta="estado")
    a.cerrar()
    lat = time.time() - t0
    for c in colgados:
        c.close()
    verificar(lat < 3, f"un cliente normal tardo {lat:.1f} s mientras habia 10 conexiones mudas")


@prueba("D4 Un cliente que envia su mensaje MUY despacio (byte a byte) no bloquea a los demas")
def _():
    msg = construir_mensaje(TYPE_REG_REQ, 1, "t-lento", "tipo=iot")
    lento = conectar(timeout=10)
    resultado = {}

    def gotea():
        for b in msg:
            lento.sendall(bytes([b]))
            time.sleep(0.03)
        resultado["resp"] = recibir_mensaje(lento)

    h = threading.Thread(target=gotea)
    h.start()
    time.sleep(0.2)
    t0 = time.time()
    a = admin()
    a.consulta(consulta="estado")
    a.cerrar()
    lat = time.time() - t0
    h.join()
    verificar(lat < 2, f"el cliente rapido tardo {lat:.1f} s por culpa del lento")
    verificar(resultado.get("resp", {}).get("tipo") == TYPE_REG_ACK,
              f"el cliente lento no recibio su REG_ACK: {resultado}")
    lento.close()


@prueba("D5 Tormenta de conexiones que se abren y cierran sin enviar nada (200)")
def _():
    for _ in range(200):
        s = conectar()
        s.close()
    time.sleep(0.5)
    a = admin()
    a.consulta(consulta="estado")
    a.cerrar()


@prueba("D6 Limite de conexiones simultaneas: las que sobran reciben SERVIDOR_OCUPADO", "limite")
def _():
    maximo = CTX.max_conexiones
    socks, rechazadas = [], 0
    for _ in range(maximo + 5):
        s = conectar(timeout=0.4)
        socks.append(s)
    for s in socks:
        try:
            r = recibir_mensaje(s)
            if es_error(r, "SERVIDOR_OCUPADO"):
                rechazadas += 1
        except (socket.timeout, ConnectionError, OSError):
            pass
    for s in socks:
        s.close()
    verificar(rechazadas == 5, f"rechazadas={rechazadas} (esperado 5)")
    time.sleep(1)
    a = admin()       # al liberar conexiones el servicio se recupera
    a.cerrar()


@prueba("Z1 El servidor sigue sano al final de todas las pruebas")
def _():
    a = admin()
    cab, regs = a.consulta(consulta="estado")
    verificar(cab.get("resultado") == "ok" and len(regs) > 0, "la consulta final fallo")
    a.cerrar()


# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Pruebas de la Fase 3 del sistema SMCD")
    ap.add_argument("host")
    ap.add_argument("puerto", type=int)
    ap.add_argument("--timeout-nodo", type=int, default=15)
    ap.add_argument("--rapido", action="store_true")
    ap.add_argument("--solo", default="")
    ap.add_argument("--max-conexiones", type=int, default=0)
    ap.add_argument("--ldap-caido", action="store_true")
    ap.add_argument("--admin", default="admin1:admin123")
    ap.add_argument("--viewer", default="viewer1:viewer123")
    a = ap.parse_args()
    CTX.host, CTX.puerto = a.host, a.puerto
    CTX.timeout_nodo = a.timeout_nodo
    CTX.max_conexiones = a.max_conexiones
    CTX.admin = tuple(a.admin.split(":", 1))
    CTX.viewer = tuple(a.viewer.split(":", 1))

    ok = fallos = omitidas = 0
    for nombre, fn, tipo in PRUEBAS:
        if a.solo and a.solo.lower() not in nombre.lower():
            continue
        if tipo == "lenta" and a.rapido:
            print(f"  [OMITIDA] {nombre}  (--rapido)")
            omitidas += 1
            continue
        if tipo == "limite" and not a.max_conexiones:
            print(f"  [OMITIDA] {nombre}  (use --max-conexiones N)")
            omitidas += 1
            continue
        if tipo == "ldap" and not a.ldap_caido:
            print(f"  [OMITIDA] {nombre}  (use --ldap-caido con slapd detenido)")
            omitidas += 1
            continue
        if tipo != "ldap" and a.ldap_caido and not a.solo:
            pass
        t0 = time.time()
        try:
            fn()
            print(f"  [OK]     {nombre}  ({time.time()-t0:.1f}s)")
            ok += 1
        except Fallo as e:
            print(f"  [FALLO]  {nombre}\n           -> {e}")
            fallos += 1
        except Exception as e:      # noqa: BLE001
            print(f"  [ERROR]  {nombre}\n           -> {type(e).__name__}: {e}")
            fallos += 1
    print(f"\nResultado: {ok} OK, {fallos} con fallos, {omitidas} omitidas")
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
