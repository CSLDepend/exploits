all:	sk
sk:	include/magic.h .depend elfuck/ef dietlibc/diet src/sk
	@(cd src; make sk)
	@dietlibc/elftrunc src/sk sk.in
	elfuck/ef -bs9 sk.in sk
	@ls -la sk
	@rm -f sk.in
.depend:
	@(cd src; ./deps)
elfuck/ef: dietlibc/diet
	@(cd elfuck; make)
dietlibc/diet:
	@(cd dietlibc; make)

include/magic.h:
	@echo "#ifndef MAGIC_H" > include/magic.h
	@echo "#define MAGIC_H" >> include/magic.h
	@echo "#define CONFMAGIC \"`od -A n --width=64 -N 64 -t x1 /dev/urandom | sed -e 's/ /\\\\x/g'`\"" >> include/magic.h
	@echo "#define CONFKEY \"`od -A n --width=64 -N 64 -t x1 /dev/urandom | sed -e 's/ /\\\\x/g'`\"" >> include/magic.h
	@echo "#endif" >> include/magic.h

include .depend

clean:
	rm -f sk core .depend include/magic.h
	@(cd src; make clean)
	@(cd elfuck; make clean)
	@(cd dietlibc; make clean)
