# Makefile

CC = gcc
LDFLAGS = -lpcap -lcurl -lncurses
CPPFLAGS = -Iinclude

SRC = src/main.c src/report_utils.c src/report.c src/route.c src/sniff.c src/storage.c src/utils.c src/llm.c src/sniper.c src/ui.c
OBJ = $(SRC:.c=.o)
TARGET = cshark

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	 ./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
