CC=gcc

all: aplssh_helpers.so

aplssh_helpers.so: aplssh_helpers.c
	$(CC) -shared -o aplssh_helpers.so -fPIC aplssh_helpers.c    
