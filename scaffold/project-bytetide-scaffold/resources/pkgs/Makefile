CC = clang
CFLAGS = -Wall -g
LDFLAGS =
OBJFILES = main.o merkletree.o
TARGET = myprogram

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

main.o: test1.c
	$(CC) $(CFLAGS) -c test1.c

merkletree.o: merkletree.c
	$(CC) $(CFLAGS) -c merkletree.c

clean:
	rm -f $(OBJFILES) $(TARGET)
