CC = gcc
CFLAGS = -Wall -g

all: servidor

servidor: servidor.c protocolo.c protocolo.h
	$(CC) $(CFLAGS) servidor.c protocolo.c -o servidor

clean:
	rm -f servidor *.o
