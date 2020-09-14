MitnickAttack: MitnickAttack.c flood.c sender.c
	 gcc -ggdb -Wall `libnet-config --defines` `libnet-config --libs` -o MitnickAttack MitnickAttack.c flood.c sender.c -I. -lnet