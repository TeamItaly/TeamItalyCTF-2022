all:
	gcc ./atomic_pizza.c -o atomic_pizza -pthread -masm=intel -Wall -Werror
	strip --strip-symbol=tricky_boy atomic_pizza

clean:
	rm atomic_pizza
