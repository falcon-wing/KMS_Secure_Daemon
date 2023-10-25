CC=gcc
CFLAGS=-I./inc -ljson-c -lpthread -lcurl -static-libgcc
THREADFLAGS=-lpthread
TARGET=rotD

OBJECT=rot_command.o mon_ifp_func.o rot_pam_conf.o rot_daemon.o mon_log.o rot_sock.o utils_file.o utils_str.o rot_utils.o mond_conf.o daemon_func.o mon_cpuinfo.o mon_meminfo.o mon_mntinfo.o mon_diskinfo.o mon_partitioninfo.o mon_log2.o
#OBJECT=mon_command.o mon_daemon.o mon_log.o rot_sock.o utils_file.o utils_str.o rot_utils.o mond_conf.o daemon_func.o
LIBSRCDIR=./libsrc
INSTALLDIR= /usr/local/ictk

$(TARGET) : $(OBJECT)
	$(CC) -o $@ $(OBJECT) $(CFLAGS)
	rm *.o

mon_command.o : rot_command.c
	$(CC) -c -o rot_command.o rot_command.c $(CFLAGS)

mon_ifp_func.o : $(LIBSRCDIR)/mon_ifp_func.c
	$(CC) -c -o mon_ifp_func.o $(LIBSRCDIR)/mon_ifp_func.c $(CFLAGS)

rot_pam_conf.o : $(LIBSRCDIR)/rot_pam_conf.c
	$(CC) -c -o rot_pam_conf.o $(LIBSRCDIR)/rot_pam_conf.c $(CFLAGS)

mon_daemon.o : rot_daemon.c
	$(CC) -c -o rot_daemon.o rot_daemon.c $(CFLAGS)

mon_log.o : $(LIBSRCDIR)/mon_log.c
	$(CC) -c -o mon_log.o $(LIBSRCDIR)/mon_log.c $(CFLAGS)

mon_log2.o : $(LIBSRCDIR)/mon_log2.c
	$(CC) -c -o mon_log2.o $(LIBSRCDIR)/mon_log2.c $(CFLAGS)

utils_file.o : $(LIBSRCDIR)/utils_file.c
	$(CC) -c -o utils_file.o $(LIBSRCDIR)/utils_file.c $(CFLAGS)

utils_str.o : $(LIBSRCDIR)/utils_str.c
	$(CC) -c -o utils_str.o $(LIBSRCDIR)/utils_str.c $(CFLAGS)

rot_utils.o : $(LIBSRCDIR)/rot_utils.c
	$(CC) -c -o rot_utils.o $(LIBSRCDIR)/rot_utils.c $(CFLAGS)

rot_sock.o : $(LIBSRCDIR)/rot_sock.c
	$(CC) -c -o rot_sock.o $(LIBSRCDIR)/rot_sock.c $(CFLAGS)

mond_conf.o : $(LIBSRCDIR)/mond_conf.c
	$(CC) -c -o mond_conf.o $(LIBSRCDIR)/mond_conf.c $(CFLAGS)

daemon_func.o : daemon_func.c
	$(CC) -c -o daemon_func.o daemon_func.c $(CFLAGS)

mon_cpuinfo.o : $(LIBSRCDIR)/mon_cpuinfo.c
	$(CC) -c -o mon_cpuinfo.o $(LIBSRCDIR)/mon_cpuinfo.c $(CFLAGS)

mon_meminfo.o : $(LIBSRCDIR)/mon_meminfo.c
	$(CC) -c -o mon_meminfo.o $(LIBSRCDIR)/mon_meminfo.c $(CFLAGS)

mon_mntinfo.o : $(LIBSRCDIR)/mon_mntinfo.c
	$(CC) -c -o mon_mntinfo.o $(LIBSRCDIR)/mon_mntinfo.c $(CFLAGS)

mon_diskinfo.o : $(LIBSRCDIR)/mon_diskinfo.c
	$(CC) -c -o mon_diskinfo.o $(LIBSRCDIR)/mon_diskinfo.c $(CFLAGS)

mon_partitioninfo.o : $(LIBSRCDIR)/mon_partitioninfo.c
	$(CC) -c -o mon_partitioninfo.o $(LIBSRCDIR)/mon_partitioninfo.c $(CFLAGS)

clean:
	rm $(OBJECT) $(TARGET)
install:
#       if pgrep $(TARGET); then pkill $(TARGET); fi
	cp -b $(TARGET) $(INSTALLDIR)/$(TARGET)
#       cd $(INSTALLDIR)
#       ./$(TARGET)
