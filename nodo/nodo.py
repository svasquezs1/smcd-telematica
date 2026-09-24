"""
Nodo simulado del sistema SMCD.

Se conecta al servidor central por TCP para registrarse, y luego envía
telemetría periódica por UDP. Cada cierto número de ciclos, además reporta
un evento crítico por TCP.

Uso:
    python3 nodo.py <host_servidor> <puerto> <id_del_nodo>

Ejemplo:
    python3 nodo.py localhost 5000 nodo-iot-01
"""

import socket
import sys
import os
import time
import random
import itertools

# Permite importar common/protocolo.py sin importar desde qué carpeta se
# ejecute este script.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from protocolo import (
    TYPE_REG_ACK, TYPE_EVENT_ACK,
    TYPE_REG_REQ, TYPE_TELEMETRY, TYPE_EVENT_REQ,
    enviar_mensaje, recibir_mensaje, enviar_datagrama,
)

contador_id = itertools.count(1)


def resolver_servidor(host, puerto):
    """
    Resuelve el nombre de host del servidor con getaddrinfo(), en vez de
    asumir una IP fija (requisito del proyecto: nada de IPs quemadas).
    Si la resolución falla, se captura la excepción y se informa sin
    finalizar el proceso abruptamente.
    """
    try:
        info = socket.getaddrinfo(host, puerto, socket.AF_INET, socket.SOCK_STREAM)
        return info[0][4]  # (ip, puerto) ya resuelto
    except socket.gaierror as e:
        print(f"[ERROR] No se pudo resolver el host '{host}': {e}")
        return None


def registrar_nodo(sock, id_nodo):
    enviar_mensaje(sock, TYPE_REG_REQ, next(contador_id), id_nodo)
    respuesta = recibir_mensaje(sock)
    if respuesta["tipo"] == TYPE_REG_ACK and respuesta["payload"] == "ok":
        print(f"[{id_nodo}] Registro exitoso.")
        return True
    print(f"[{id_nodo}] Registro rechazado: {respuesta}")
    return False


def enviar_telemetria(sock_udp, direccion, id_nodo):
    cpu = round(random.uniform(10, 95), 1)
    payload = f"tipo=cpu;valor={cpu};unidad=%;timestamp={int(time.time())}"
    enviar_datagrama(sock_udp, direccion, TYPE_TELEMETRY, next(contador_id), id_nodo, payload)
    print(f"[{id_nodo}] TELEMETRY enviada: {payload}")


def reportar_evento(sock_tcp, id_nodo):
    payload = "tipo=umbral_superado;metrica=cpu;valor=97.2"
    enviar_mensaje(sock_tcp, TYPE_EVENT_REQ, next(contador_id), id_nodo, payload)
    respuesta = recibir_mensaje(sock_tcp)
    if respuesta["tipo"] == TYPE_EVENT_ACK:
        print(f"[{id_nodo}] Evento confirmado por el servidor.")
    else:
        print(f"[{id_nodo}] Evento rechazado: {respuesta}")


def main():
    if len(sys.argv) != 4:
        print(f"Uso: python3 {sys.argv[0]} <host_servidor> <puerto> <id_del_nodo>")
        sys.exit(1)

    host, puerto, id_nodo = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    direccion = resolver_servidor(host, puerto)
    if direccion is None:
        sys.exit(1)

    # --- Registro por TCP ---
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock_tcp.connect(direccion)
    except (ConnectionRefusedError, OSError) as e:
        print(f"[ERROR] No se pudo conectar al servidor: {e}")
        sys.exit(1)

    if not registrar_nodo(sock_tcp, id_nodo):
        sock_tcp.close()
        sys.exit(1)

    # --- Telemetría por UDP (mismo número de puerto, socket distinto) ---
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ciclos = 0
    try:
        while True:
            enviar_telemetria(sock_udp, direccion, id_nodo)
            ciclos += 1

            # Cada 5 ciclos, simula un evento crítico (por TCP)
            if ciclos % 5 == 0:
                reportar_evento(sock_tcp, id_nodo)

            time.sleep(3)
    except KeyboardInterrupt:
        print(f"\n[{id_nodo}] Deteniendo nodo...")
    except ConnectionError as e:
        print(f"[ERROR] Se perdió la conexión con el servidor: {e}")
    finally:
        sock_tcp.close()
        sock_udp.close()


if __name__ == "__main__":
    main()
