CC = gcc
CFLAGS = -Wall -Wno-unused-result -O2
OBJECTS = MD5.o

all: hash_cracker

hash_cracker: $(OBJECTS)

MD5.o: MD5.c MD5.h
	$(CC) $(CFLAGS) MD5.c -o MD5

#run: hash_cracker
#	./MD5

clean:
	rm -rf *o
