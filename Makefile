OBJS = tpm12.o pcrtool.o md.o fprintpcr.o
HDRS = tpm12.h md.h tpm_common.h

ifeq ($(DEBUG),yes)
CFLAGS = -g -DTSS_DEBUG
else
CFLASG = -O3
endif

pcrtool: $(OBJS)
	gcc -o $@ $(OBJS) -lcrypto -lssl -ltspi

%.o: %.c $(HDRS)
	gcc -Wall $(CFLAGS) -c -o $@ $<

clean:
	-rm pcrtool *.o
