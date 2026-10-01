#!/usr/bin/env python3
"""
Nodo simulado del sistema SMCD (sensor IoT o equipo de red/servidor).

Que hace:
  1. Resuelve el nombre del servidor y se REGISTRA por TCP (REG_REQ / REG_ACK).
  2. Envia TELEMETRIA periodica por UDP (sin confirmacion: si se pierde una,
     la siguiente la reemplaza).
  3. Cuando una metrica supera su umbral (o falla aleatoriamente) envia un
     EVENTO critico por TCP y espera el EVENT_ACK; si no llega, lo REINTENTA
     con el MISMO id (el servidor detecta el duplicado y no lo guarda dos veces).
  4. Si la conexion se cae o el servidor no responde, el nodo NO termina:
     reintenta con espera creciente y vuelve a registrarse.

Uso:
    python3 nodo.py <host_servidor> <puerto> <id_nodo> [--tipo iot|red|servidor]
                    [--intervalo 3] [--prob-falla 0.02]

Ejemplos:
    python3 nodo.py localhost 5000 sensor-01 --tipo iot
    python3 nodo.py servidor-smcd.local 5000 router-02 --tipo red --intervalo 2
"""
import argparse
import itertools
import os
import random
import select
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from protocolo import (  # noqa: E402
    TYPE_REG_REQ, TYPE_REG_ACK, TYPE_TELEMETRY, TYPE_EVENT_REQ, TYPE_EVENT_ACK, TYPE_ERROR,
    enviar_mensaje, recibir_mensaje, enviar_datagrama, construir_payload, parsear_payload,
    resolver, ErrorProtocolo,
)

ESPERA_MAX_REINTENTO = 15      # segundos (tope de la espera creciente)
TIMEOUT_ACK = 5                # segundos esperando REG_ACK / EVENT_ACK
REINTENTOS_EVENTO = 3          # veces que se reenvia un evento sin ACK
ENFRIAMIENTO_EVENTO = 20       # segundos minimos entre eventos del mismo tipo


def log(id_nodo, texto):
    print(f"[{time.strftime('%H:%M:%S')}] [{id_nodo}] {texto}", flush=True)


class Simulador:
    """Genera metricas verosimiles segun el tipo de nodo (caminata aleatoria)."""

    def __init__(self, tipo):
        self.tipo = tipo
        self.v = {"temp": 35.0, "bateria": 100.0, "humedad": 50.0,
                  "cpu": 30.0, "mem": 40.0, "latencia_ms": 20.0, "disco": 55.0}

    def _paso(self, nombre, delta, minimo, maximo):
        self.v[nombre] = min(maximo, max(minimo, self.v[nombre] + random.uniform(-delta, delta)))
        return round(self.v[nombre], 1)

    def muestra(self):
        if self.tipo == "iot":
            self.v["bateria"] = max(0.0, self.v["bateria"] - random.uniform(0.0, 0.4))
            if self.v["bateria"] < 5:
                self.v["bateria"] = 100.0           # "recarga"
            return {"temp": self._paso("temp", 4, 15, 95), "bateria": round(self.v["bateria"], 1),
                    "humedad": self._paso("humedad", 3, 10, 95)}
        if self.tipo == "red":
            return {"cpu": self._paso("cpu", 12, 2, 100), "mem": self._paso("mem", 4, 10, 98),
                    "latencia_ms": self._paso("latencia_ms", 40, 1, 400)}
        return {"cpu": self._paso("cpu", 12, 2, 100), "mem": self._paso("mem", 4, 10, 98),
                "disco": self._paso("disco", 1, 20, 99)}

    @staticmethod
    def alertas(m):
        """Devuelve [(metrica, valor, umbral)] para las metricas fuera de rango."""
        reglas = {"temp": (">", 80), "bateria": ("<", 15), "cpu": (">", 90),
                  "mem": (">", 90), "latencia_ms": (">", 250), "disco": (">", 95)}
        salida = []
        for nombre, valor in m.items():
            if nombre in reglas:
                op, umbral = reglas[nombre]
                if (op == ">" and valor > umbral) or (op == "<" and valor < umbral):
                    salida.append((nombre, valor, umbral))
        return salida


class Nodo:
    def __init__(self, args):
        self.a = args
        self.id = args.id_nodo
        self.sim = Simulador(args.tipo)
        self.contador = itertools.count(1)
        self.tcp = None
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.destino_udp = None
        self.pendientes = []                 # eventos aun sin confirmar: (id, payload)
        self.ultimo_evento = {}              # metrica -> instante del ultimo evento

    # ------------------------------------------------------------------ red
    def _cerrar_tcp(self):
        if self.tcp:
            try:
                self.tcp.close()
            except OSError:
                pass
        self.tcp = None

    def conectar_y_registrar(self):
        """Resuelve el nombre, conecta y registra. Devuelve True si quedo registrado."""
        destino = resolver(self.a.host, self.a.puerto)
        if destino is None:
            log(self.id, f"no se pudo resolver '{self.a.host}' (se reintentara)")
            return False
        self.destino_udp = resolver(self.a.host, self.a.puerto, socket.SOCK_DGRAM) or destino
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT_ACK)
            s.connect(destino)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            enviar_mensaje(s, TYPE_REG_REQ, next(self.contador), self.id, f"tipo={self.a.tipo}")
            r = recibir_mensaje(s)
        except (OSError, ConnectionError, ErrorProtocolo) as e:
            log(self.id, f"no se pudo registrar: {e}")
            try:
                s.close()
            except Exception:       # noqa: BLE001
                pass
            return False
        campos = parsear_payload(r["payload"])
        if r["tipo"] == TYPE_REG_ACK and campos.get("resultado") == "ok":
            self.tcp = s
            log(self.id, f"REGISTRADO en {destino[0]}:{destino[1]} (sesion {campos.get('sesion')})")
            return True
        log(self.id, f"registro rechazado: {campos.get('codigo', campos)} {campos.get('detalle', '')}")
        s.close()
        return False

    def conexion_viva(self):
        """Detecta que el servidor cerro la conexion aunque este ociosa."""
        if not self.tcp:
            return False
        try:
            listo, _, _ = select.select([self.tcp], [], [], 0)
            if listo:
                dato = self.tcp.recv(1, socket.MSG_PEEK)
                if dato == b"":
                    return False                      # cierre ordenado del servidor
                r = recibir_mensaje(self.tcp)         # mensaje no solicitado (p. ej. ERROR)
                campos = parsear_payload(r["payload"])
                log(self.id, f"el servidor envio: {campos.get('codigo', r['payload'])}")
                if r["tipo"] == TYPE_ERROR:
                    return False
        except (OSError, ConnectionError, ErrorProtocolo):
            return False
        return True

    # ------------------------------------------------------------ mensajes
    def enviar_telemetria(self, muestra):
        enviar_datagrama(self.udp, self.destino_udp, TYPE_TELEMETRY, next(self.contador),
                         self.id, construir_payload(muestra))

    def entregar_eventos(self):
        """Envia los eventos pendientes, con reintentos y el MISMO id. False si se perdio la conexion."""
        while self.pendientes:
            id_msg, payload = self.pendientes[0]
            confirmado = False
            for intento in range(1, REINTENTOS_EVENTO + 1):
                try:
                    enviar_mensaje(self.tcp, TYPE_EVENT_REQ, id_msg, self.id, payload)
                    r = recibir_mensaje(self.tcp)
                except (socket.timeout, TimeoutError):
                    log(self.id, f"sin EVENT_ACK (intento {intento}/{REINTENTOS_EVENTO}), se reenvia con el mismo id={id_msg}")
                    continue
                except (OSError, ConnectionError, ErrorProtocolo) as e:
                    log(self.id, f"conexion perdida enviando evento: {e}")
                    return False
                campos = parsear_payload(r["payload"])
                if r["tipo"] == TYPE_EVENT_ACK:
                    extra = " (duplicado: el servidor ya lo tenia)" if campos.get("duplicado") == "1" else ""
                    log(self.id, f"evento id={id_msg} CONFIRMADO{extra}")
                    confirmado = True
                    break
                log(self.id, f"evento rechazado: {campos.get('codigo')} {campos.get('detalle', '')}")
                confirmado = True      # un rechazo no se arregla reenviando: se descarta
                break
            if not confirmado:
                return False           # 3 intentos sin respuesta: se considera caida la conexion
            self.pendientes.pop(0)
        return True

    def evaluar_eventos(self, muestra):
        ahora = time.time()
        for nombre, valor, umbral in self.sim.alertas(muestra):
            if ahora - self.ultimo_evento.get(nombre, 0) >= ENFRIAMIENTO_EVENTO:
                self.ultimo_evento[nombre] = ahora
                payload = construir_payload({"tipo": "umbral_superado", "metrica": nombre,
                                             "valor": valor, "umbral": umbral, "severidad": "alta"})
                self.pendientes.append((next(self.contador), payload))
        if random.random() < self.a.prob_falla and ahora - self.ultimo_evento.get("falla", 0) >= ENFRIAMIENTO_EVENTO:
            self.ultimo_evento["falla"] = ahora
            payload = construir_payload({"tipo": "falla_hardware", "severidad": "critica"})
            self.pendientes.append((next(self.contador), payload))

    # ------------------------------------------------------------ bucle
    def correr(self):
        espera = 1
        log(self.id, f"iniciado (tipo={self.a.tipo}, intervalo={self.a.intervalo}s). Ctrl+C para detener")
        while True:
            if not self.tcp or not self.conexion_viva():
                if self.tcp:
                    log(self.id, "se perdio la conexion con el servidor")
                self._cerrar_tcp()
                if not self.conectar_y_registrar():
                    log(self.id, f"reintentando en {espera}s")
                    time.sleep(espera)
                    espera = min(espera * 2, ESPERA_MAX_REINTENTO)
                    continue
                espera = 1

            muestra = self.sim.muestra()
            self.enviar_telemetria(muestra)
            log(self.id, "TELEMETRY " + " ".join(f"{k}={v}" for k, v in muestra.items()))
            self.evaluar_eventos(muestra)
            if self.pendientes and not self.entregar_eventos():
                self._cerrar_tcp()           # se reconectara en la proxima vuelta
            time.sleep(self.a.intervalo)


def main():
    ap = argparse.ArgumentParser(description="Nodo simulado del sistema SMCD")
    ap.add_argument("host", help="nombre del servidor (no una IP fija)")
    ap.add_argument("puerto", type=int)
    ap.add_argument("id_nodo", help="identificador del nodo: letras, numeros, '.', '_' y '-'")
    ap.add_argument("--tipo", choices=["iot", "red", "servidor"], default="iot")
    ap.add_argument("--intervalo", type=float, default=3.0, help="segundos entre telemetrias")
    ap.add_argument("--prob-falla", type=float, default=0.02, help="probabilidad de falla por ciclo")
    args = ap.parse_args()
    nodo = Nodo(args)
    try:
        nodo.correr()
    except KeyboardInterrupt:
        log(args.id_nodo, "detenido por el usuario")
    finally:
        nodo._cerrar_tcp()
        nodo.udp.close()


if __name__ == "__main__":
    main()
