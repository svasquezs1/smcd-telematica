#!/usr/bin/env python3
"""
Cliente de administracion del sistema SMCD.

Permite a un usuario autenticado (LDAP) consultar la infraestructura:
  1) Estado instantaneo de todos los nodos
  2) Historial de un nodo (las ultimas muestras, hasta 10)
  3) Bitacora de eventos criticos (solo perfil admin)
  4) Monitor en vivo (se actualiza cada 3 s)

El cliente NUNCA habla con los nodos: todo pasa por el servidor central.

Uso:
    python3 cliente_admin.py <host_servidor> <puerto> <usuario>

La contrasena se pide por teclado sin mostrarla (getpass). Para automatizar
pruebas tambien puede darse en la variable de entorno SMCD_PASSWORD.
"""
import argparse
import getpass
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from protocolo import (  # noqa: E402
    TYPE_AUTH_REQ, TYPE_AUTH_ACK, TYPE_QUERY_REQ, TYPE_QUERY_RESP, TYPE_ERROR,
    enviar_mensaje, recibir_mensaje, construir_payload, parsear_payload, parsear_registros,
    resolver, ErrorProtocolo,
)

TIMEOUT_RESPUESTA = 10          # segundos esperando una respuesta del servidor
MAX_INTENTOS_LOGIN = 3
USAR_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

MENSAJES_ERROR = {
    "ACCESO_DENEGADO": "Su perfil no tiene permiso para esta consulta.",
    "NODO_DESCONOCIDO": "Ese nodo no existe en el sistema.",
    "SERVICIO_AUTH_NO_DISPONIBLE": "El servicio de autenticacion (LDAP) no esta disponible. Intente mas tarde.",
    "SERVIDOR_OCUPADO": "El servidor esta lleno. Intente de nuevo en un momento.",
    "SESION_INVALIDA": "La sesion no es valida. Inicie sesion otra vez.",
    "PARAMETRO_INVALIDO": "El servidor rechazo los parametros de la consulta.",
}


class ErrorServidor(Exception):
    def __init__(self, codigo, detalle):
        super().__init__(f"{codigo}: {detalle}")
        self.codigo, self.detalle = codigo, detalle


class ConexionPerdida(Exception):
    pass


def color(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m" if USAR_COLOR else texto


def hora(ts):
    return time.strftime("%H:%M:%S", time.localtime(int(ts)))


# ---------------------------------------------------------------------------
class Cliente:
    def __init__(self, host, puerto, usuario):
        self.host, self.puerto, self.usuario = host, puerto, usuario
        self.password = os.environ.get("SMCD_PASSWORD")
        self.sock = None
        self.token = None
        self.perfil = None
        self.n = 0

    # -- conexion ----------------------------------------------------------
    def cerrar(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def conectar(self):
        """Conecta al servidor; si falla (DNS, servidor caido) reintenta sin terminar."""
        espera = 1
        while True:
            destino = resolver(self.host, self.puerto)
            if destino is None:
                print(f"No se pudo resolver el nombre '{self.host}'. Reintentando en {espera}s... (Ctrl+C para salir)")
            else:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT_RESPUESTA)
                    s.connect(destino)
                    self.sock = s
                    return
                except OSError as e:
                    print(f"No se pudo conectar a {destino[0]}:{destino[1]} ({e}). Reintentando en {espera}s... (Ctrl+C para salir)")
            time.sleep(espera)
            espera = min(espera * 2, 10)

    def _pedir(self, tipo, payload):
        self.n += 1
        try:
            enviar_mensaje(self.sock, tipo, self.n, self.usuario, payload)
            return recibir_mensaje(self.sock)
        except (ConnectionError, socket.timeout, TimeoutError, OSError, ErrorProtocolo) as e:
            self.cerrar()
            raise ConexionPerdida(str(e))

    # -- sesion ------------------------------------------------------------
    def iniciar_sesion(self):
        """Conecta y autentica. Devuelve True si quedo autenticado."""
        for intento in range(1, MAX_INTENTOS_LOGIN + 1):
            if not self.sock:
                self.conectar()
            if self.password is None:
                self.password = getpass.getpass(f"Contrasena de {self.usuario}: ")
            try:
                r = self._pedir(TYPE_AUTH_REQ, construir_payload({"usuario": self.usuario, "password": self.password}))
            except ConexionPerdida:
                print("Se perdio la conexion durante el inicio de sesion.")
                continue
            campos = parsear_payload(r["payload"])
            if r["tipo"] == TYPE_AUTH_ACK and campos.get("resultado") == "ok":
                self.token, self.perfil = campos["sesion"], campos["perfil"]
                return True
            if r["tipo"] == TYPE_ERROR:
                print(color("✗ " + MENSAJES_ERROR.get(campos.get("codigo"), campos.get("detalle", "error")), "31"))
                self.cerrar()
                time.sleep(2)
                continue
            print(color(f"✗ Usuario o contrasena incorrectos (intento {intento}/{MAX_INTENTOS_LOGIN})", "31"))
            self.password = None
            if intento < MAX_INTENTOS_LOGIN and not os.environ.get("SMCD_PASSWORD"):
                continue
            break
        return False

    def consultar(self, **campos):
        r = self._pedir(TYPE_QUERY_REQ, construir_payload({"sesion": self.token, **campos}))
        if r["tipo"] == TYPE_ERROR:
            c = parsear_payload(r["payload"])
            raise ErrorServidor(c.get("codigo", "?"), c.get("detalle", ""))
        if r["tipo"] != TYPE_QUERY_RESP:
            raise ErrorServidor("RESPUESTA_INESPERADA", f"tipo {r['tipo']}")
        return parsear_registros(r["payload"])


# ---------------------------------------------------------------------------
# Presentacion
# ---------------------------------------------------------------------------
SIMBOLO_ESTADO = {
    "ACTIVO": ("● ACTIVO", "32"),
    "INACTIVO": ("◐ INACTIVO", "33"),
    "DESCONECTADO": ("○ DESCONECTADO", "31"),
}


def imprimir_tabla(encabezados, filas, formatos=None):
    """filas: lista de listas de str. formatos: {indice_columna: funcion(texto)->texto con color}"""
    formatos = formatos or {}
    anchos = [max(len(str(x)) for x in col) for col in zip(encabezados, *filas)] if filas else [len(h) for h in encabezados]
    linea = lambda celdas: "  ".join(  # noqa: E731
        (formatos[i](str(c).ljust(anchos[i])) if i in formatos else str(c).ljust(anchos[i]))
        for i, c in enumerate(celdas))
    print(color(linea(encabezados), "1"))
    print("  ".join("─" * a for a in anchos))
    for f in filas:
        print(linea(f))


def metricas_texto(datos):
    return "  ".join(f"{k}={v}" for k, v in datos.items()) if datos else "(sin telemetria todavia)"


def mostrar_estado(cab, regs):
    print(f"\nEstado de la infraestructura — {len(regs)} nodo(s)  [{time.strftime('%H:%M:%S')}]\n")
    if not regs:
        print("  (todavia no hay nodos registrados)")
        return
    filas, estados = [], []
    for meta, datos in regs:
        texto, _ = SIMBOLO_ESTADO.get(meta.get("estado"), (meta.get("estado", "?"), "0"))
        estados.append(meta.get("estado"))
        filas.append([meta["nodo"], meta.get("tipo", "?"), texto, f"{meta.get('visto_hace', '?')}s",
                      meta.get("eventos", "0"), metricas_texto(datos)])

    def pintar_estado(celda):
        for nombre, (texto, cod) in SIMBOLO_ESTADO.items():
            if celda.strip() == texto:
                return color(celda, cod)
        return celda
    imprimir_tabla(["NODO", "TIPO", "ESTADO", "VISTO HACE", "EVENTOS", "ULTIMAS METRICAS"], filas, {2: pintar_estado})


def mostrar_historial(nodo, cab, regs):
    print(f"\nHistorial de '{nodo}' — {len(regs)} muestra(s), de la mas reciente a la mas antigua\n")
    if not regs:
        print("  (el nodo todavia no ha enviado telemetria)")
        return
    filas = [[hora(m["ts"]), f"hace {m['hace']}s", metricas_texto(d)] for m, d in regs]
    imprimir_tabla(["HORA", "ANTIGUEDAD", "METRICAS"], filas)


def mostrar_eventos(cab, regs):
    print(f"\nEventos criticos — {len(regs)} (del mas reciente al mas antiguo)\n")
    if not regs:
        print("  (no hay eventos registrados)")
        return
    filas = []
    for m, d in regs:
        detalle = "  ".join(f"{k}={v}" for k, v in d.items() if k not in ("tipo", "severidad", "origen"))
        filas.append([hora(m["ts"]), m["nodo"], d.get("severidad", "-"), d.get("tipo", "?"), detalle])

    def pintar_sev(celda):
        s = celda.strip()
        return color(celda, "31") if s in ("alta", "critica") else color(celda, "33") if s == "media" else celda
    imprimir_tabla(["HORA", "NODO", "SEVERIDAD", "EVENTO", "DETALLE"], filas, {2: pintar_sev})


# ---------------------------------------------------------------------------
# Acciones del menu
# ---------------------------------------------------------------------------
def accion_estado(cli):
    mostrar_estado(*cli.consultar(consulta="estado"))


def accion_historial(cli):
    _, nodos = cli.consultar(consulta="estado")
    ids = [m["nodo"] for m, _ in nodos]
    if not ids:
        print("\n(todavia no hay nodos registrados)")
        return
    print("\nNodos disponibles:")
    for i, nid in enumerate(ids, 1):
        print(f"  {i}. {nid}")
    eleccion = input("Nodo (numero o id): ").strip()
    nodo = ids[int(eleccion) - 1] if eleccion.isdigit() and 1 <= int(eleccion) <= len(ids) else eleccion
    cuantas = input("Cuantas muestras (1-10, Enter = 10): ").strip()
    campos = {"consulta": "historial", "nodo": nodo}
    if cuantas:
        campos["n"] = cuantas
    mostrar_historial(nodo, *cli.consultar(**campos))


def accion_eventos(cli):
    mostrar_eventos(*cli.consultar(consulta="eventos"))


def accion_monitor(cli):
    print("Monitor en vivo. Ctrl+C para volver al menu.")
    time.sleep(0.5)
    try:
        while True:
            cab, regs = cli.consultar(consulta="estado")
            print("\033[H\033[J" if USAR_COLOR else "\n" + "=" * 70, end="")
            mostrar_estado(cab, regs)
            print("\n(se actualiza cada 3 s — Ctrl+C para volver)")
            time.sleep(3)
    except KeyboardInterrupt:
        print()


ACCIONES = {"1": accion_estado, "2": accion_historial, "3": accion_eventos, "4": accion_monitor}


def menu(cli):
    while True:
        print(f"\n── SMCD ── usuario: {cli.usuario} (perfil: {cli.perfil}) ──────────")
        print("  1) Estado actual de los nodos")
        print("  2) Historial de un nodo")
        print("  3) Eventos criticos" + ("" if cli.perfil == "admin" else "  [requiere perfil admin]"))
        print("  4) Monitor en vivo")
        print("  0) Salir")
        try:
            op = input("Opcion: ").strip()
        except EOFError:
            return
        if op == "0":
            return
        accion = ACCIONES.get(op)
        if not accion:
            print("Opcion no valida.")
            continue
        try:
            accion(cli)
        except ErrorServidor as e:
            print(color(f"✗ {MENSAJES_ERROR.get(e.codigo, e.detalle)}  [{e.codigo}]", "31"))
        except ConexionPerdida as e:
            print(color(f"✗ Se perdio la conexion con el servidor ({e}). Reconectando...", "31"))
            if not cli.iniciar_sesion():
                print("No fue posible volver a iniciar sesion.")
                return
            print(color("✓ Sesion restablecida.", "32"))


def main():
    ap = argparse.ArgumentParser(description="Cliente de administracion SMCD")
    ap.add_argument("host", help="nombre del servidor (no una IP fija)")
    ap.add_argument("puerto", type=int)
    ap.add_argument("usuario")
    args = ap.parse_args()

    cli = Cliente(args.host, args.puerto, args.usuario)
    try:
        if not cli.iniciar_sesion():
            print("No fue posible autenticarse.")
            return 1
        print(color(f"✓ Autenticado como {cli.usuario} (perfil: {cli.perfil})", "32"))
        menu(cli)
    except KeyboardInterrupt:
        print()
    finally:
        cli.cerrar()
    print("Hasta luego.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
