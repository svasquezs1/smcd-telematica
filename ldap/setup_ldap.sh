#!/bin/bash
# Instala y configura OpenLDAP para el proyecto SMCD en Ubuntu y carga los usuarios de prueba.
# Uso:   sudo ./ldap/setup_ldap.sh
#
# Resultado:
#   - dominio dc=smcd,dc=local, administrador cn=admin,dc=smcd,dc=local (clave: adminpass)
#   - usuarios admin1/admin123 (perfil admin) y viewer1/viewer123 (perfil viewer)
#
# Nota: si slapd YA estaba instalado con otro dominio, ejecute antes
#       "sudo dpkg-reconfigure slapd" y elija smcd.local, o adapte las variables.
set -e
cd "$(dirname "$0")"

DOMINIO="smcd.local"
BASE="dc=smcd,dc=local"
ADMIN_DN="cn=admin,$BASE"
ADMIN_PASS="adminpass"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ejecute este script con sudo." >&2
    exit 1
fi

echo "==> Instalando paquetes (slapd, ldap-utils, libldap2-dev, gcc, make)..."
export DEBIAN_FRONTEND=noninteractive
echo "slapd slapd/domain string $DOMINIO"            | debconf-set-selections
echo "slapd shared/organization string SMCD"          | debconf-set-selections
echo "slapd slapd/password1 password $ADMIN_PASS"     | debconf-set-selections
echo "slapd slapd/password2 password $ADMIN_PASS"     | debconf-set-selections
echo "slapd slapd/no_configuration boolean false"     | debconf-set-selections
apt-get update -qq
apt-get install -y slapd ldap-utils libldap2-dev gcc make

echo "==> Iniciando el servicio slapd..."
systemctl enable --now slapd 2>/dev/null || service slapd start 2>/dev/null || true

echo "==> Esperando a que LDAP responda..."
for i in $(seq 1 15); do
    if ldapsearch -x -H ldap://localhost -b "$BASE" -s base >/dev/null 2>&1; then break; fi
    sleep 1
done
ldapsearch -x -H ldap://localhost -b "$BASE" -s base >/dev/null 2>&1 || {
    echo "slapd no responde en ldap://localhost. Revise: sudo systemctl status slapd" >&2; exit 1; }

echo "==> Cargando usuarios de prueba..."
if ldapsearch -x -H ldap://localhost -b "ou=people,$BASE" -s base >/dev/null 2>&1; then
    echo "    (ou=people ya existe: no se vuelven a cargar)"
else
    ldapadd -x -H ldap://localhost -D "$ADMIN_DN" -w "$ADMIN_PASS" -f usuarios.ldif
fi

echo "==> Verificando autenticacion de los usuarios..."
ldapwhoami -x -H ldap://localhost -D "uid=admin1,ou=people,$BASE"  -w admin123  && echo "    admin1  OK"
ldapwhoami -x -H ldap://localhost -D "uid=viewer1,ou=people,$BASE" -w viewer123 && echo "    viewer1 OK"
echo "LDAP listo."
