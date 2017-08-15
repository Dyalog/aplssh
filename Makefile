CC=gcc

all: aplhelpers.so

aplhelpers.so: aplhelpers.c
	$(CC) -shared -o aplhelpers.so -fPIC aplhelpers.c    
