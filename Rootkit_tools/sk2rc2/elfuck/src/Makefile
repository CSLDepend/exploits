CC=dietlibc/diet -Os gcc
CFLAGS=-Wall -O2 -fomit-frame-pointer -I../include
LDFLAGS=-s
.c.o:
	$(CC) $(CFLAGS) -c $<
.S.o:
	$(CC) $(CFLAGS) -c $<
elfuck:elfuck.o getpw.o nrv2e.o poly.o stubify.o decompress.o execelf.o lock.o
clean:
	rm -f *.o elfuck core
elfuck.o: ../include/elfuck.h ../include/stubify.h
getpw.o: ../include/elfuck.h ../include/lock.h ../include/getpw.h
nrv2e.o:
poly.o: ../include/elfuck.h ../include/poly.h
stubify.o: ../include/nrv2e.h ../include/elfuck.h ../include/decompress.h ../include/execelf.h ../include/stubify.h ../include/poly.h ../include/getpw.h ../include/lock.h
../include/decompress.h:
../include/elfuck.h:
../include/execelf.h:
../include/getpw.h:
../include/lock.h:
../include/nrv2e.h: ../include/elfuck.h
../include/poly.h:
../include/stubify.h:
