CC ?= gcc
CFLAGS ?= -Wall -Werror -g
LDFLAGS ?=

TARGET = aesdsocket

all: $(TARGET)
default: $(TARGET)

$(TARGET): aesdsocket.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)
