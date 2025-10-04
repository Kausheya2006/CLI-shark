# Makefile

CC = gcc
LDFLAGS = -lpcap

SRC = main.c
OBJ = $(SRC:.c=.o)
TARGET = cshark

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
