.SUFFIXES : .c .o
CFLAGS = -g -lcrypto -lssl

OBJS = root_ca.o sign_csr.o

SRCS = $(OBJS:.o=.c)
HFILES = common.h
EXE = root_ca

exe : $(OBJS) $(HFILES)
	$(CC) -o $(EXE) $(OBJS) $(CFLAGS)

clean :
	rm -rf $(EXE)
	rm -f *.o core core.*
