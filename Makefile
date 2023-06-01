APP=ressible
OBJS=hci.o ressible.o cJSON.o bluetooth.o

all: $(APP)

ressible: $(OBJS)
	gcc -o $(APP) $(OBJS)

%.o: %.c %.h
	gcc -g -o $*.o -c $*.c

clean:
	rm -f $(OBJS)
