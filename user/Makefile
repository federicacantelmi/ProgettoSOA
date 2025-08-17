CC = gcc
CFLAGS = -Wall -Wextra -g -I../include

all: snapshot_user

snapshot_user: snapshot_user.c
	$(CC) $(CFLAGS) -o snapshot_user snapshot_user.c

clean:
	rm -f snapshot_user