# Directories and Files
BUILD_DIR = build
SNIFFER_DIR = sniffer
ANALYSIS_DIR = analysis
SNIFFER_TARGET = $(BUILD_DIR)/sniffer_app

# Compiler
CC := gcc
CFLAGS := -g -Wall -Wextra
LDFLAGS = -lpcap

CFLAGS += -I$(ANALYSIS_DIR)

# Sniffer
SRC := $(wildcard $(SNIFFER_DIR)/*.c $(ANALYSIS_DIR)/*.c)
OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRC))

sniffer: $(SNIFFER_TARGET)

$(SNIFFER_TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

sniff: $(SNIFFER_TARGET)
	sudo $(SNIFFER_TARGET)

clean:
	rm -rf $(SNIFFER_TARGET) $(BUILD_DIR)

