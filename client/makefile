.SUFFIXES : .c .o
CFLAGS = -g -lcrypto -lssl

OBJS = client.o ecdsa.o send_certificate.o client_fork.o

SRCS = $(OBJS:.o=.c)
HFILES = common.h
EXE = client

exe : $(OBJS) $(HFILES)
	$(CC) -o $(EXE) $(OBJS) $(CFLAGS)

clean :
	rm -rf $(EXE)
	rm -f *.o core core.*
