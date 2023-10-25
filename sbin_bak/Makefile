CC=gcc
CFLAGS=-I./inc -ljson-c -lpthread -lcurl
THREADFLAGS=-lpthread
TARGET=ictk_wd

OBJECT=conf.o ictk_wd.o mon_log2.o utils.o
LIBSRCDIR=./libsrc
INSTALLDIR= /usr/local/ictk

$(TARGET) : $(OBJECT)
	$(CC) -o $@ $(OBJECT) $(CFLAGS)
	rm *.o

conf.o : conf.c
	$(CC) -c -o conf.o conf.c $(CFLAGS)

utils.o : utils.c
	$(CC) -c -o utils.o utils.c $(CFLAGS)

mon_log2.o : mon_log2.c
	$(CC) -c -o mon_log2.o mon_log2.c $(CFLAGS)

ictk_wd.o : ictk_wd.c
	$(CC) -c -o ictk_wd.o ictk_wd.c $(CFLAGS)

clean:
	rm $(OBJECT) $(TARGET)

install:
	cp -b $(TARGET) $(INSTALLDIR)/$(TARGET)
