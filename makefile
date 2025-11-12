# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -pthread
LDFLAGS = -lpcap -pthread

# Directories
SRC_DIR = src
UTILS_DIR = $(SRC_DIR)/utils
CAPTURE_DIR = $(SRC_DIR)/capture
PARSER_DIR = $(SRC_DIR)/parser
OUTPUT_DIR = $(SRC_DIR)/output
ANALYSIS_DIR = $(SRC_DIR)/analysis
BUILD_DIR = build
BIN_DIR = bin

# Target
TARGET = $(BIN_DIR)/Lodestone

# Source files
SOURCES = \
	$(SRC_DIR)/main.c \
	$(UTILS_DIR)/packet.c \
	$(UTILS_DIR)/buffer.c \
	$(UTILS_DIR)/checksum.c \
	$(UTILS_DIR)/hash.c \
	$(CAPTURE_DIR)/capture.c \
	$(CAPTURE_DIR)/mmap_capture.c \
	$(CAPTURE_DIR)/filter.c \
	$(PARSER_DIR)/parser.c \
	$(PARSER_DIR)/ethernet.c \
	$(PARSER_DIR)/ip.c \
	$(PARSER_DIR)/ipv6.c \
	$(PARSER_DIR)/tcp.c \
	$(PARSER_DIR)/udp.c \
	$(PARSER_DIR)/icmp.c \
	$(PARSER_DIR)/icmpv6.c \
	$(PARSER_DIR)/arp.c \
	$(PARSER_DIR)/dns.c \
	$(PARSER_DIR)/http.c \
	$(OUTPUT_DIR)/display.c \
	$(OUTPUT_DIR)/pcap_writer.c \
	$(OUTPUT_DIR)/logger.c \
	$(OUTPUT_DIR)/stats.c \
	$(ANALYSIS_DIR)/stream.c \
	$(ANALYSIS_DIR)/detector.c

# Object files
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Create directories
$(shell mkdir -p $(BUILD_DIR)/utils $(BUILD_DIR)/capture $(BUILD_DIR)/parser $(BUILD_DIR)/output $(BUILD_DIR)/analysis $(BIN_DIR))

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(OBJECTS)
	@echo "Linking $@"
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	@echo "Cleaning build files..."
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Clean complete"

# Install (requires root)
install: $(TARGET)
	@echo "Installing to /usr/local/bin..."
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "Installation complete"

# Uninstall
uninstall:
	@echo "Uninstalling..."
	rm -f /usr/local/bin/Lodestone
	@echo "Uninstall complete"

# Debug build
debug: CFLAGS += -g -DDEBUG -O0
debug: clean $(TARGET)

# Enable checksum validation
checksums: CFLAGS += -DVALIDATE_CHECKSUMS
checksums: clean $(TARGET)

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build the packet sniffer (default)"
	@echo "  clean      - Remove build files"
	@echo "  install    - Install to /usr/local/bin (requires root)"
	@echo "  uninstall  - Uninstall from /usr/local/bin"
	@echo "  debug      - Build with debug symbols"
	@echo "  checksums  - Build with checksum validation enabled"
	@echo "  help       - Show this help message"

.PHONY: all clean install uninstall debug checksums help