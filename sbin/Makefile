CC=gcc
CFLAGS=-I./inc -ljson-c -lpthread -lcurl
THREADFLAGS=-lpthread
TARGET=wd_worker

OBJECT= mon_log.o utils.o wd_worker.o
LIBSRCDIR=./libsrc
INSTALLDIR= /usr/local/ictk

$(TARGET) : $(OBJECT)
	$(CC) -o $@ $(OBJECT) $(CFLAGS)
	rm *.o

mon_log.o : $(LIBSRCDIR)/mon_log.c
	$(CC) -c -o mon_log.o $(LIBSRCDIR)/mon_log.c $(CFLAGS)	

wd_worker.o : wd_worker.c
	$(CC) -c -o wd_worker.o wd_worker.c $(CFLAGS)

utils.o : $(LIBSRCDIR)/utils.c
	$(CC) -c -o utils.o $(LIBSRCDIR)/utils.c $(CFLAGS)

clean:
	rm $(OBJECT) $(TARGET)
install:
	cp -b $(TARGET) $(INSTALLDIR)/$(TARGET)


