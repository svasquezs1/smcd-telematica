"""
Módulo compartido para construir y parsear mensajes del protocolo NMP
(Node Monitoring Protocol). Usado tanto por los nodos como por el cliente
de administración.

Ver la especificación completa en la wiki del repositorio
(página "Especificación del Protocolo NMP").
"""

# Tipos de mensaje — deben coincidir exactamente con protocolo.h del servidor en C
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


def construir_mensaje(tipo, id_msg, origen, payload=""):
    """Arma la cadena de bytes de un mensaje NMP listo para enviar."""
    payload_bytes = payload.encode("utf-8")
    encabezado = (
        f"NMP/1.0\n"
        f"TYPE:{tipo}\n"
        f"ID:{id_msg}\n"
        f"FROM:{origen}\n"
        f"LEN:{len(payload_bytes)}\n"
        f"\n"
    )
    return encabezado.encode("utf-8") + payload_bytes


def _recv_linea(sock):
    """Lee del socket TCP byte por byte hasta encontrar '\\n' (no incluido)."""
    linea = b""
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("Conexión cerrada por el servidor")
        if b == b"\n":
            break
        linea += b
    return linea.decode("utf-8")


def _recv_exacto(sock, n):
    """Lee exactamente n bytes del socket TCP, acumulando en un bucle."""
    datos = b""
    while len(datos) < n:
        fragmento = sock.recv(n - len(datos))
        if not fragmento:
            raise ConnectionError("Conexión cerrada por el servidor")
        datos += fragmento
    return datos


def recibir_mensaje(sock):
    """
    Recibe y parsea un mensaje NMP completo desde un socket TCP.
    Retorna un diccionario: {"tipo": int, "id": int, "from": str, "payload": str}
    """
    _recv_linea(sock)  # línea "NMP/1.0", se descarta

    tipo = id_msg = origen = length = None
    while True:
        linea = _recv_linea(sock)
        if linea == "":
            break  # línea en blanco: fin de la cabecera
        if linea.startswith("TYPE:"):
            tipo = int(linea[len("TYPE:"):])
        elif linea.startswith("ID:"):
            id_msg = int(linea[len("ID:"):])
        elif linea.startswith("FROM:"):
            origen = linea[len("FROM:"):]
        elif linea.startswith("LEN:"):
            length = int(linea[len("LEN:"):])

    if None in (tipo, id_msg, origen, length):
        raise ValueError("Cabecera NMP incompleta")

    payload = _recv_exacto(sock, length).decode("utf-8") if length > 0 else ""

    return {"tipo": tipo, "id": id_msg, "from": origen, "payload": payload}


def enviar_mensaje(sock, tipo, id_msg, origen, payload=""):
    """Construye y envía un mensaje NMP completo por un socket TCP."""
    sock.sendall(construir_mensaje(tipo, id_msg, origen, payload))


def enviar_datagrama(sock, direccion, tipo, id_msg, origen, payload=""):
    """Construye y envía un mensaje NMP como un único datagrama UDP."""
    sock.sendto(construir_mensaje(tipo, id_msg, origen, payload), direccion)
