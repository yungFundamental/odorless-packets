CC := gcc
CFLAGS := -g
BUILD_DIR := build
SNIFFER_BIN := sniffer

build-sniffer:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) sniffer/main.c -lpcap -o $(BUILD_DIR)/$(SNIFFER_BIN)

sniff: $(BUILD_DIR)/$(SNIFFER_BIN)
	sudo $(BUILD_DIR)/$(SNIFFER_BIN)

