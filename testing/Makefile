CC = g++
INCLUDE= "-I../riscv/"

.PHONY: all

bloom.o: ../riscv/bloom.cc
	$(CC) -c -o $@ $< $(INCLUDE)

ibda_hash.o: ../riscv/ibda_hash.cc
	$(CC) -c -o $@ $< $(INCLUDE)

unit_test.o: unit_test.cc
	$(CC) -c -o $@ $< $(INCLUDE)

all: unit_test.o ibda_hash.o bloom.o
	$(CC) -o run.X unit_test.o ibda_hash.o bloom.o

.PHONY: clean

clean:
	rm -f *.o *.X