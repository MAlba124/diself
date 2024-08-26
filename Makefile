CFLAGS = -O2 -Wall -Wextra -std=c99 -march=native

defualt: build

.PHONY: build
build: main.c
	$(CC) $(CFLAGS) main.c -o diself

.PHONY: clean
clean:
	@rm diself

.PHONY: run
run: build
	./diself

.PHONY: check
check:
	$(CC) $(CFLAGS) -fsyntax-only main.c
