all:
	gcc -Wall -I . ./main.c -o ./main.o -lpcap

clean:
	rm -f ./main