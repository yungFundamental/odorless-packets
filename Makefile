# Directories and Files
BUILD_DIR = build
SNIFFER_DIR = sniffer
ANALYSIS_DIR = frame_analysis
OVERRIDE_DIR = override

SNIFFER_BIN = $(BUILD_DIR)/sniffer_app
ANALYSIS_LIB = $(BUILD_DIR)/frame_analysis.a
OVERRIDE_SO  := $(BUILD_DIR)/libpcap_override.so

# Compiler
CC := gcc
CFLAGS := -g -Wall -Wextra -fPIC -I$(ANALYSIS_DIR)
LDFLAGS = -lpcap

CFLAGS += -I$(ANALYSIS_DIR) -fPIC

# Sources
SNIFFER_SRC  := $(wildcard $(SNIFFER_DIR)/*.c)
SNIFFER_OBJ  := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SNIFFER_SRC))

ANALYSIS_SRC := $(wildcard $(ANALYSIS_DIR)/*.c)
ANALYSIS_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(ANALYSIS_SRC))

OVERRIDE_SRC := $(wildcard $(OVERRIDE_DIR)/*.c)
OVERRIDE_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(OVERRIDE_SRC))

all: $(SNIFFER_BIN) $(OVERRIDE_SO)

sniffer: $(SNIFFER_BIN)

$(SNIFFER_BIN): $(SNIFFER_OBJ) $(ANALYSIS_LIB)
	$(CC) $(CFLAGS) -o $@ $(SNIFFER_OBJ) $(ANALYSIS_LIB) $(LDFLAGS)

$(ANALYSIS_LIB): $(ANALYSIS_OBJ)
	ar rcs $@ $^

$(OVERRIDE_SO): $(OVERRIDE_OBJ) $(ANALYSIS_LIB)
	$(CC) $(CFLAGS) -shared -o $@ $^

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

sniff: $(SNIFFER_BIN)
	@echo "Running sniffer on default interface (without LD_PRELOAD):"
	sudo $(SNIFFER_BIN)

fake-sniff: $(SNIFFER_BIN) $(OVERRIDE_SO)
	@echo "Running sniffer on default interface (with LD_PRELOAD):"
	sudo LD_PRELOAD=$(OVERRIDE_SO) $(SNIFFER_BIN)

clean:
	rm -rf $(SNIFFER_BIN) $(ANALYSIS_LIB) $(OVERRIDE_SO) $(BUILD_DIR)

