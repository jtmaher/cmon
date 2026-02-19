CC = gcc
CFLAGS = -Wall -Wextra -Wno-format-truncation -O2 -I deps/include
LDFLAGS = -L deps/lib -lncursesw -ltinfo -lm
TARGET = cmon
SRCS = cmon.c cJSON.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

cmon.o: cmon.c cJSON.h
	$(CC) $(CFLAGS) -c -o $@ $<

cJSON.o: cJSON.c cJSON.h
	$(CC) -Wall -O2 -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
