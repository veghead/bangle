all: ressible hci.c hcitool.c cJSON.c

ressible: hci.o hcitool.o bluetooth.o cJSON.o
	gcc -o ressible hci.o hcitool.o bluetooth.o cJSON.o

%.o: %.c %.h
	gcc -g -o $*.o -c $*.c
