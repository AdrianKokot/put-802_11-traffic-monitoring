all:
	gcc -Wall ./main.c -o ./main.o -lpcap

clean:
	rm -f ./main