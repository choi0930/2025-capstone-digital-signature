.SUFFIXES : .c .o
CFLAGS = -g -lcrypto -lssl

OBJS = client.o ecdsa.o send_certificate.o client_fork.o client_to_server.o client_to_ca.o make_csr.o cert_get_pubkey.o

SRCS = $(OBJS:.o=.c)
HFILES = common.h
EXE = client

exe : $(OBJS) $(HFILES)
	$(CC) -o $(EXE) $(OBJS) $(CFLAGS)

clean :
	rm -rf $(EXE)
	rm -f *.o core core.*
