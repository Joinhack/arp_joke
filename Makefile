CC=gcc
LIBS=-lpcap -lm

OBJ=main.o util.o
	
arp_joke:$(OBJ)
	$(CC) -o arp_joke $(OBJ) $(LIBS)
	
all:arp_joke
	
