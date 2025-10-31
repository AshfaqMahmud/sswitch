CC = gcc
CFLAGS = -Wall -Iinclude
LDFLAGS = -lpcap

SRC = src/main.c src/capture.c src/forwarding.c src/mac_table.c src/utils.c
OBJ = $(SRC:.c=.o)

software_switch: $(OBJ)
	$(CC) $(OBJ) -o software_switch $(LDFLAGS)

clean:
	rm -f src/*.o software_switch
