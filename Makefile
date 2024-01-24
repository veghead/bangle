OBJS=hci.o hciwrap.o cJSON.o bluetooth.o

all: adlog bangle

adlog: $(OBJS) adlog.o
	gcc -o $@ $(OBJS) $@.o

bangle: $(OBJS) adlog.o
	gcc -o $@ $(OBJS) $@.o

%.o: %.c
	gcc -g -o $*.o -c $*.c

clean:
	rm -f $(OBJS)
