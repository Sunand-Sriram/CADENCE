CC      := clang
CFLAGS  := -g -O1 -fsanitize=address,fuzzer,undefined -fno-sanitize-recover=undefined -Wall -include crypto_shim.h
HARNESS := fuzz_harness
SRCS    := fuzz_harness.c vuln.c crypto_stubs.c

.PHONY: all test clean

all: $(HARNESS)

$(HARNESS): $(SRCS)
	$(CC) $(CFLAGS) -o $(HARNESS) $(SRCS)

test: $(HARNESS)
	./$(HARNESS) fixtures/good1
	./$(HARNESS) fixtures/good2
	@echo "regression: all known-good inputs passed"

clean:
	rm -f $(HARNESS) *.o
