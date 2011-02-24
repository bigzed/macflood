# Makefile for macflood
SHELL = /bin/sh

.SUFFIXES:
.SUFFIXES: .c .o

CC=gcc
AR=ar
CFLAGS = -Wall -g
SRC = ./src

LIBNET = -lnet
LIBPTHREAD = -lm -D_REENTRANT -lpthread
LIBPCAP = -lpcap


macflood: $(SRC)/macflood.o
	      $(CC) $(LIBPTHREAD) $(LIBPCAP) $(LIBNET) $(SRC)/libspork.c $(SRC)/macflood.c -o macflood


clean:
	      rm macflood *.o *.a

