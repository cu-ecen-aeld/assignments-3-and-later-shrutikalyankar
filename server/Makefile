CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror -Wextra -O2
TARGET ?= aesdsocket
SRC := aesdsocket.c
OBJ := $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -pthread -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -pthread -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
