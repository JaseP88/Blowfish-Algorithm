## makefile 

CC = cc
OPS = -g

all: blow

blow: blowfish.o
	$(CC) $(OPS) -o blow blowfish.c blowfish_consts.c

clean:
	rm -f *.o
	rm -f blow
