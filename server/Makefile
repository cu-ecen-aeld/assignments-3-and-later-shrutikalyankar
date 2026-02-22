CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror -Wextra -O2
LDFLAGS ?=
TARGET ?= aesdsocket
SRC := aesdsocket.c
OBJ := $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -pthread

%.o: %.c
	$(CC) $(CFLAGS) -pthread -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
