APP=bangle
OBJS=hci.o bangle.o cJSON.o bluetooth.o

all: $(APP)

$(APP): $(OBJS)
	gcc -o $(APP) $(OBJS)

%.o: %.c
	gcc -g -o $*.o -c $*.c

clean:
	rm -f $(OBJS)
