# Makefile

CC = gcc
LDFLAGS = -lpcap -lcurl

SRC = main.c report_utils.c report.c route.c sniff.c storage.c utils.c llm.c
OBJ = $(SRC:.c=.o)
TARGET = cshark

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
