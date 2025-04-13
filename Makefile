TARGET = netfilter
SRC = netfilter.c

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) -lnetfilter_queue

clean:
	rm -f $(TARGET)

.PHONY: clean
