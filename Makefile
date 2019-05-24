all: cipher

cipher cipher.c:
	gcc cipher.c -o cipher

clean:
	rm cipher
