# Directories and Files
BUILD_DIR = build
SNIFFER_DIR = sniffer
ANALYSIS_DIR = analysis
OVERRIDE_DIR = override
SNIFFER_TARGET = $(BUILD_DIR)/sniffer_app

# Compiler
CC := gcc
CFLAGS := -g -Wall -Wextra
LDFLAGS = -lpcap

CFLAGS += -I$(ANALYSIS_DIR) -fPIC

# Sniffer
SRC := $(wildcard $(SNIFFER_DIR)/*.c $(ANALYSIS_DIR)/*.c)
OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRC))

# Override code
OVERRIDE_SRC := $(wildcard $(OVERRIDE_DIR)/*.c)
OVERRIDE_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(OVERRIDE_SRC))
OVERRIDE_SO  := $(BUILD_DIR)/libpcap_override.so

all: $(TARGET) $(OVERRIDE_SO)

sniffer: $(SNIFFER_TARGET)

$(SNIFFER_TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OVERRIDE_SO): $(OVERRIDE_OBJ)
	$(CC) -shared -fPIC -o $@ $^


sniff: $(SNIFFER_TARGET)
	sudo $(SNIFFER_TARGET)

fake-sniff: $(SNIFFER_TARGET) $(OVERRIDE_SO)
	sudo LD_PRELOAD=$(OVERRIDE_SO) $(SNIFFER_TARGET)

clean:
	rm -rf $(SNIFFER_TARGET) $(BUILD_DIR)

