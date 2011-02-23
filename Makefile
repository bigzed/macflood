# Makefile for macflood
SHELL = /bin/sh

.SUFFIXES:
.SUFFIXES: .c .o

CC=gcc
CFLAGS = -Wall -g
LDFLAGS = -lm -D_REENTRANT -lnet -lpcap -lpthread

macflood: macflood.o
	      $(CC) $(LDFLAGS) -o $@ $^

clean:
	      rm macflood *.o

