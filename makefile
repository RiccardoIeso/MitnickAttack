MitnickAttack: MitnickAttack.c flood.c sender.c
	gcc -ggdb -std=gnu99 -Wall -pthread -o MitnickAttack MitnickAttack.c flood.c sender.c packetsniffer.c -I. -lnet -lpcap