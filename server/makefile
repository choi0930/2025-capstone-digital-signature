.SUFFIXES : .c .o
CFLAGS = -g -lcrypto -lssl

OBJS = server.o ecdsaVerify.o recv_pub_key.o
SRCS = $(OBJS:.o=.c)
HFILES = common.h
EXE = server

exe : $(OBJS) $(HFILES)
	$(CC) -o $(EXE) $(OBJS) $(CFLAGS)

clean :
	rm -rf $(EXE)
	rm -f *.o core core.*
