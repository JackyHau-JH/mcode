all:snake maes
snake:snake.c
	gcc -o $@ $< -lSDL2

maes:maes.c
	gcc -o $@ $<  -lcrypto
	#gcc -o $@ $<  -lssl -lcrypto 
#snake:snake.c
#	gcc -o snake snake.c -lSDL2

.PHONY:clean
clean:
	rm -rf snake maes
