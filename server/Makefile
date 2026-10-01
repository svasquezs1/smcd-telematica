CC     = gcc
CFLAGS = -Wall -Wextra -g -pthread
LIBS   = -lldap -llber
OBJ_SERVIDOR = servidor.c protocolo.c estado.c log.c auth_ldap.c

all: servidor

servidor: $(OBJ_SERVIDOR) protocolo.h estado.h log.h auth.h
	$(CC) $(CFLAGS) $(OBJ_SERVIDOR) -o servidor $(LIBS)

test_protocolo: test_protocolo.c protocolo.c protocolo.h
	$(CC) $(CFLAGS) test_protocolo.c protocolo.c -o test_protocolo

test: test_protocolo
	./test_protocolo

clean:
	rm -f servidor test_protocolo *.o
