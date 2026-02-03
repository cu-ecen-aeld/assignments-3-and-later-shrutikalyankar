# Compiler
CC := gcc

# Compiler flags
CFLAGS := -Wall -Werror

# Target name
TARGET := writer

# Source files
SRC := writer.c
OBJ := $(SRC:.c=.o)

# Default target
all: $(TARGET)

# Build the writer application
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: all clean
