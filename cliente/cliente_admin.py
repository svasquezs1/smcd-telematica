"""
Cliente de administración del sistema SMCD.

Se autentica contra el servidor y consulta el estado de los nodos
registrados. En esta Fase 2 el servidor usa un mecanismo de autenticación
simplificado (siempre acepta); la integración real contra LDAP se
implementa en la Fase 3 (ver Bloque 6 y página "Autenticación" de la wiki).

Uso:
    python3 cliente_admin.py <host_servidor> <puerto> <usuario>
"""

import socket
import sys
import os
import itertools

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from protocolo import (
    TYPE_AUTH_ACK, TYPE_QUERY_RESP,
    TYPE_AUTH_REQ, TYPE_QUERY_REQ,
    enviar_mensaje, recibir_mensaje,
)

contador_id = itertools.count(1)


def resolver_servidor(host, puerto):
    try:
        info = socket.getaddrinfo(host, puerto, socket.AF_INET, socket.SOCK_STREAM)
        return info[0][4]
    except socket.gaierror as e:
        print(f"[ERROR] No se pudo resolver el host '{host}': {e}")
        return None


def autenticar(sock, usuario):
    # Fase 2: contraseña de ejemplo fija, solo para probar el flujo del
    # protocolo. En Fase 3 se pedirá de forma segura (getpass) y viajará
    # hacia una validación real contra LDAP en el servidor.
    payload = f"usuario={usuario};password=demo123"
    enviar_mensaje(sock, TYPE_AUTH_REQ, next(contador_id), usuario, payload)
    respuesta = recibir_mensaje(sock)
    if respuesta["tipo"] == TYPE_AUTH_ACK and respuesta["payload"] == "ok":
        print(f"Autenticación exitosa para '{usuario}'.")
        return True
    print(f"Autenticación rechazada: {respuesta}")
    return False


def consultar_estado(sock, usuario):
    enviar_mensaje(sock, TYPE_QUERY_REQ, next(contador_id), usuario, "consulta=todos")
    respuesta = recibir_mensaje(sock)
    if respuesta["tipo"] == TYPE_QUERY_RESP:
        print("\nEstado actual de los nodos:")
        print(respuesta["payload"] if respuesta["payload"] else "(sin nodos registrados aún)")
    else:
        print(f"Consulta rechazada: {respuesta}")


def main():
    if len(sys.argv) != 4:
        print(f"Uso: python3 {sys.argv[0]} <host_servidor> <puerto> <usuario>")
        sys.exit(1)

    host, puerto, usuario = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    direccion = resolver_servidor(host, puerto)
    if direccion is None:
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(direccion)
    except (ConnectionRefusedError, OSError) as e:
        print(f"[ERROR] No se pudo conectar al servidor: {e}")
        sys.exit(1)

    if not autenticar(sock, usuario):
        sock.close()
        sys.exit(1)

    try:
        while True:
            input("\nPresiona Enter para consultar el estado (Ctrl+C para salir): ")
            consultar_estado(sock, usuario)
    except KeyboardInterrupt:
        print("\nCerrando cliente...")
    except ConnectionError as e:
        print(f"[ERROR] Se perdió la conexión con el servidor: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
