CC=gcc
CFLAGS=-c 
LPCAP=-lpcap 
SOURCES=main.c vector.c analyzer.c 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=analyzer

all: $(SOURCES) $(LPCAP) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LPCAP) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o analyzer