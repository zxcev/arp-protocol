CC = gcc
CFLAGS = -Wall -Wextra -I.

SRC = main.c
TARGET = dist/main.out

# includes all the header files in the current directory
HEADERS = $(wildcard *.h)

# default target
all: $(TARGET)
# rules for elf creation
$(TARGET): $(SRC) $(HEADERS)
	@mkdir -p dist
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean

