OBJS = tpm12.o tpm2.o pcrtool.o md.o fprintpcr.o
HDRS = tpm12.h md.h tpm_common.h tpm2.h tpm2_mg_alg.h
CC = gcc
CFLAGS = -Wall

ifeq ($(DEBUG),yes)
CFLAGS += -g -DTSS_DEBUG
else
CFLASG += -O3
endif

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

pcrtool: $(OBJS)
	$(CC) -o $@ $(OBJS) -lcrypto -lssl -ltspi -lsapi -ltcti-socket

clean:
	-rm pcrtool *.o
