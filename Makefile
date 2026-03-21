CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_DEFAULT_SOURCE -I/usr/include/libnl3
LDFLAGS = -lnl-3 -lnl-genl-3

SRC_DIR = src
BUILD_DIR = build
TARGET = wifi-scanner

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/scanner.c $(SRC_DIR)/parser.c $(SRC_DIR)/display.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install check

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

check:
	@echo "Checking dependencies..."
	@dpkg -l | grep -q libnl-3-dev || echo "libnl-3-dev not installed"
	@dpkg -l | grep -q libnl-genl-3-dev || echo "libnl-genl-3-dev not installed"

install-deps:
	@echo "Installing dependencies..."
	@sudo apt-get update && sudo apt-get install -y libnl-3-dev libnl-genl-3-dev

clean:
	rm -f $(TARGET) $(SRC_DIR)/*.o

run: $(TARGET)
	sudo ./$(TARGET) -i wlp2s0
