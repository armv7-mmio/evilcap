CC := gcc
CFLAGS := -Wall -Wextra -O3
LDFLAGS := -s -O3
BUILD_DIR := ./build
BIN_DIR := ./bin
MODULES := earp

TARGETS := $(addprefix $(BIN_DIR)/, $(MODULES))
SRCS :=

include earp/earp.mk

OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRCS))

all: $(TARGETS)

$(TARGETS): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(wildcard $(BUILD_DIR)/$(notdir $@)/*.o) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $< -o $@ $(CFLAGS) -I./$(dir $<)include

clean: 
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean

