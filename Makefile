CC = gcc
SRC = printing.c packet.c main.o
OBJS = $(SRC:.c=.o)
OUT = sniffy

all: $(OUT)

%.o: %.c
	$(CC) -c $<

$(OUT): $(OBJS)
	$(CC) -o $@ $(OBJS)

.PHONY: clean

clean:
	rm -f $(OBJS)
	rm -f $(OUT)
