"""
Modulo compartido del protocolo NMP (Node Monitoring Protocol) para Python.
Lo usan los nodos y el cliente de administracion.

Debe mantenerse consistente con server/protocolo.c y con la especificacion
publicada en la wiki del repositorio.

Formato de un mensaje (texto plano):

    NMP/1.0
    TYPE:<codigo>
    ID:<numero>
    FROM:<identificador>
    LEN:<bytes del payload>
    <linea en blanco>
    <payload>

El payload es una lista de pares clave=valor separados por ';'. Los VALORES se
codifican con %XX (igual que en una URL) para poder llevar ';', '=', '%' y
cualquier otro caracter sin ambiguedad.
"""
import re
import socket
from urllib.parse import quote, unquote

# --- Tipos de mensaje (iguales a server/protocolo.h) ---
TYPE_REG_REQ = 1
TYPE_REG_ACK = 2
TYPE_TELEMETRY = 3
TYPE_EVENT_REQ = 4
TYPE_EVENT_ACK = 5
TYPE_AUTH_REQ = 6
TYPE_AUTH_ACK = 7
TYPE_QUERY_REQ = 8
TYPE_QUERY_RESP = 9
TYPE_ERROR = 10

NOMBRES_TIPO = {
    TYPE_REG_REQ: "REG_REQ", TYPE_REG_ACK: "REG_ACK",
    TYPE_TELEMETRY: "TELEMETRY", TYPE_EVENT_REQ: "EVENT_REQ",
    TYPE_EVENT_ACK: "EVENT_ACK", TYPE_AUTH_REQ: "AUTH_REQ",
    TYPE_AUTH_ACK: "AUTH_ACK", TYPE_QUERY_REQ: "QUERY_REQ",
    TYPE_QUERY_RESP: "QUERY_RESP", TYPE_ERROR: "ERROR",
}

MAX_PAYLOAD = 8192
_ID_VALIDO = re.compile(r"^[A-Za-z0-9._-]{1,63}$")


class ErrorProtocolo(Exception):
    """El otro extremo envio algo que no cumple el protocolo NMP."""


# ---------------------------------------------------------------------------
# Payloads clave=valor
# ---------------------------------------------------------------------------
def codificar(valor):
    """Codifica un valor para ponerlo en un payload (%XX)."""
    return quote(str(valor), safe="")


def construir_payload(campos):
    """{'a': 1, 'b': 'x;y'} -> 'a=1;b=x%3By' (respeta el orden del dict)."""
    return ";".join(f"{k}={codificar(v)}" for k, v in campos.items())


def parsear_payload(texto):
    """'a=1;b=x%3By' -> {'a': '1', 'b': 'x;y'} (valores ya decodificados)."""
    campos = {}
    if not texto:
        return campos
    for segmento in texto.split(";"):
        if "=" not in segmento:
            continue
        clave, valor = segmento.split("=", 1)
        campos[clave] = unquote(valor)
    return campos


def parsear_registros(payload):
    """
    Interpreta la respuesta a una consulta (QUERY_RESP).

    Formato:  primera linea = cabecera (resultado, consulta, registros)
              lineas siguientes = 'meta|datos' (una por registro)

    Devuelve (cabecera: dict, registros: [(meta: dict, datos: dict), ...])
    """
    lineas = payload.split("\n")
    cabecera = parsear_payload(lineas[0])
    registros = []
    for linea in lineas[1:]:
        if not linea:
            continue
        meta, _, datos = linea.partition("|")
        registros.append((parsear_payload(meta), parsear_payload(datos)))
    return cabecera, registros


# ---------------------------------------------------------------------------
# Construccion y lectura de mensajes
# ---------------------------------------------------------------------------
def construir_mensaje(tipo, id_msg, origen, payload=""):
    """Arma los bytes de un mensaje NMP listo para enviar."""
    if not _ID_VALIDO.match(origen):
        raise ValueError(f"Identificador invalido para FROM: {origen!r} "
                         "(solo letras, numeros, '.', '_' y '-', maximo 63)")
    cuerpo = payload.encode("utf-8")
    if len(cuerpo) >= MAX_PAYLOAD:
        raise ValueError("Payload demasiado grande")
    cabecera = (f"NMP/1.0\nTYPE:{tipo}\nID:{id_msg}\nFROM:{origen}\n"
                f"LEN:{len(cuerpo)}\n\n")
    return cabecera.encode("utf-8") + cuerpo


def _recv_linea(sock):
    """Lee una linea del socket TCP (byte a byte) sin incluir el '\\n'."""
    linea = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("conexion cerrada por el servidor")
        if b == b"\n":
            break
        linea += b
        if len(linea) > 256:
            raise ErrorProtocolo("linea de cabecera demasiado larga")
    return linea.decode("utf-8", errors="replace").rstrip("\r")


def _recv_exacto(sock, n):
    """Lee exactamente n bytes (TCP es un flujo: un recv puede traer menos)."""
    datos = bytearray()
    while len(datos) < n:
        trozo = sock.recv(n - len(datos))
        if not trozo:
            raise ConnectionError("conexion cerrada por el servidor")
        datos += trozo
    return bytes(datos)


def recibir_mensaje(sock):
    """
    Lee un mensaje NMP completo desde un socket TCP.

    Devuelve {"tipo": int, "id": int, "from": str, "payload": str}
    Puede lanzar:
      ConnectionError  -> el servidor cerro la conexion
      socket.timeout   -> no llego respuesta a tiempo (si el socket tiene timeout)
      ErrorProtocolo   -> el servidor envio un mensaje mal formado
    """
    if _recv_linea(sock) != "NMP/1.0":
        raise ErrorProtocolo("version de protocolo desconocida")
    tipo = id_msg = origen = longitud = None
    while True:
        linea = _recv_linea(sock)
        if linea == "":
            break
        try:
            if linea.startswith("TYPE:"):
                tipo = int(linea[5:])
            elif linea.startswith("ID:"):
                id_msg = int(linea[3:])
            elif linea.startswith("FROM:"):
                origen = linea[5:]
            elif linea.startswith("LEN:"):
                longitud = int(linea[4:])
        except ValueError:
            raise ErrorProtocolo(f"cabecera invalida: {linea!r}")
    if None in (tipo, id_msg, origen, longitud) or not 0 <= longitud < MAX_PAYLOAD:
        raise ErrorProtocolo("cabecera NMP incompleta o LEN fuera de rango")
    payload = _recv_exacto(sock, longitud).decode("utf-8", errors="replace") if longitud else ""
    return {"tipo": tipo, "id": id_msg, "from": origen, "payload": payload}


def enviar_mensaje(sock, tipo, id_msg, origen, payload=""):
    """Construye y envia un mensaje NMP completo por un socket TCP."""
    sock.sendall(construir_mensaje(tipo, id_msg, origen, payload))


def enviar_datagrama(sock, direccion, tipo, id_msg, origen, payload=""):
    """Construye y envia un mensaje NMP como un unico datagrama UDP."""
    sock.sendto(construir_mensaje(tipo, id_msg, origen, payload), direccion)


def resolver(host, puerto, tipo_socket=socket.SOCK_STREAM):
    """
    Resuelve un nombre de host a (ip, puerto) con getaddrinfo().
    Devuelve None si la resolucion falla (el llamador decide si reintenta):
    el programa NO debe terminar por un fallo de resolucion de nombres.
    """
    try:
        info = socket.getaddrinfo(host, puerto, socket.AF_INET, tipo_socket)
        return info[0][4]
    except (socket.gaierror, OSError):
        return None
