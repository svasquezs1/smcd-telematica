#!/usr/bin/env python3
"""
Prueba de RESILIENCIA: que pasa si el servidor se cae y vuelve a levantarse.

Arranca por su cuenta el servidor y un nodo, mata el servidor de golpe (SIGKILL)
y comprueba que:
  - el nodo NO termina: detecta la caida y reintenta con espera creciente;
  - cuando el servidor vuelve, el nodo se REGISTRA de nuevo solo;
  - el cliente de administracion detecta la perdida de conexion y puede
    volver a iniciar sesion;
  - un nodo apuntando a un nombre inexistente (fallo de DNS) sigue vivo.

Requiere: servidor compilado (make -C server) y el servicio LDAP funcionando.
Uso:  python3 pruebas/prueba_resiliencia.py [--puerto 5055]
"""
import argparse
import os
import signal
import subprocess
import sys
import time

RAIZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(RAIZ, "common"))
sys.path.insert(0, os.path.join(RAIZ, "cliente"))
import cliente_admin  # noqa: E402

fallos = 0


def paso(texto):
    print(f"\n>> {texto}")


def verificar(cond, ok, mal):
    global fallos
    if cond:
        print(f"   [OK]    {ok}")
    else:
        print(f"   [FALLO] {mal}")
        fallos += 1


def lanzar_servidor(puerto, log):
    return subprocess.Popen([os.path.join(RAIZ, "server", "servidor"), str(puerto), log],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env={**os.environ, "SMCD_TIMEOUT_NODO": "6"})


def esperar(cond, timeout):
    fin = time.time() + timeout
    while time.time() < fin:
        if cond():
            return True
        time.sleep(0.3)
    return cond()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--puerto", type=int, default=5055)
    ap.add_argument("--admin", default="admin1:admin123")
    a = ap.parse_args()
    usuario, clave = a.admin.split(":", 1)
    salida_nodo = "/tmp/resiliencia_nodo.out"
    log = "/tmp/resiliencia_servidor.log"

    paso("1. Arrancar servidor y un nodo")
    srv = lanzar_servidor(a.puerto, log)
    time.sleep(1)
    with open(salida_nodo, "w") as f:
        nodo = subprocess.Popen([sys.executable, os.path.join(RAIZ, "nodo", "nodo.py"), "localhost",
                                 str(a.puerto), "nodo-resiliente", "--intervalo", "1", "--prob-falla", "0"],
                                stdout=f, stderr=subprocess.STDOUT)
    leer = lambda: open(salida_nodo).read()  # noqa: E731
    verificar(esperar(lambda: "REGISTRADO" in leer(), 8), "el nodo se registro", "el nodo no se registro")

    paso("2. Un cliente de administracion inicia sesion y ve al nodo")
    cliente_admin.USAR_COLOR = False
    cli = cliente_admin.Cliente("localhost", a.puerto, usuario)
    cli.password = clave
    verificar(cli.iniciar_sesion(), f"cliente autenticado (perfil {cli.perfil})", "no se pudo autenticar (esta LDAP encendido?)")
    _, regs = cli.consultar(consulta="estado")
    verificar(any(m["nodo"] == "nodo-resiliente" and m["estado"] == "ACTIVO" for m, _ in regs),
              "el nodo aparece ACTIVO", "el nodo no aparece ACTIVO")

    paso("3. MATAR el servidor de golpe (SIGKILL)")
    srv.send_signal(signal.SIGKILL)
    srv.wait()
    time.sleep(4)
    verificar(nodo.poll() is None, "el nodo SIGUE VIVO sin servidor", "el nodo termino al caerse el servidor")
    verificar("se perdio la conexion" in leer(), "el nodo detecto la caida", "el nodo no detecto la caida")
    verificar("reintentando" in leer(), "el nodo esta reintentando conectarse", "el nodo no reintenta")
    try:
        cli.consultar(consulta="estado")
        verificar(False, "", "el cliente deberia haber detectado la conexion caida")
    except cliente_admin.ConexionPerdida:
        verificar(True, "el cliente detecto la perdida de conexion", "")

    paso("4. Volver a levantar el servidor")
    srv2 = lanzar_servidor(a.puerto, log)
    registros_antes = leer().count("REGISTRADO")
    verificar(esperar(lambda: leer().count("REGISTRADO") > registros_antes, 25),
              "el nodo se REGISTRO DE NUEVO automaticamente", "el nodo no volvio a registrarse")
    cli.cerrar()
    verificar(cli.iniciar_sesion(), "el cliente volvio a iniciar sesion", "el cliente no pudo reconectar")
    time.sleep(2)
    _, regs = cli.consultar(consulta="estado")
    verificar(any(m["nodo"] == "nodo-resiliente" and m["estado"] == "ACTIVO" for m, _ in regs),
              "el nodo vuelve a aparecer ACTIVO en el servidor nuevo", "el nodo no aparece ACTIVO")
    cli.cerrar()

    paso("5. Un nodo con un nombre de servidor que NO existe (fallo de DNS)")
    salida2 = "/tmp/resiliencia_nodo2.out"
    with open(salida2, "w") as f:
        n2 = subprocess.Popen([sys.executable, os.path.join(RAIZ, "nodo", "nodo.py"),
                               "servidor-que-no-existe.invalid", str(a.puerto), "nodo-sin-dns",
                               "--intervalo", "1"], stdout=f, stderr=subprocess.STDOUT)
    time.sleep(6)
    verificar(n2.poll() is None, "el nodo sigue vivo pese a no resolver el nombre", "el nodo termino por el fallo de DNS")
    verificar("no se pudo resolver" in open(salida2).read(), "informa el fallo y reintenta", "no informo el fallo de DNS")

    for p in (nodo, n2):
        p.terminate()
    srv2.send_signal(signal.SIGINT)
    srv2.wait(timeout=10)
    print(f"\nResultado: {'TODO OK' if not fallos else str(fallos) + ' fallo(s)'}")
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
