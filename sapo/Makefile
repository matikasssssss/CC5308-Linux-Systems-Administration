CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -g
LDFLAGS  = 

TARGET   = sapo

SRCS     = $(wildcard *.c)
OBJS     = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)