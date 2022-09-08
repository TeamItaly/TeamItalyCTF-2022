#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>


#define MAX_SLICES 0x10

typedef struct {
	__uint16_t size;
	char topping[];
} Slice;

Slice* pizza[MAX_SLICES];
Slice* favorite_slice;

bool is_spinning;

#pragma pack(1)
struct {
	char pad[15];
	Slice* yoink;
} tricky_boy;


void print_menu();
void new_slice();
void admire_slice();
void change_topping();
void eat_slice();
void select_favorite_slice();
void remember_favorite_slice();
void change_favorits_slice_topping();

void* pizza_spinner(void* args);

void get_topping(char* topping, size_t size);
size_t read_integer();
void assert_fail(bool condition, const char* fmt, ...);



__attribute__ ((constructor)) void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	puts("                                                                                      ");
	puts("   PI    ZZAPI   ZZAP    I    Z   Z    APIZ        ZAPIZ    Z  APIZZA  PIZZAP    IZ   ");
	puts("  Z  A     P    I    Z   ZA  PI   Z   Z    A       P    I   Z      Z       A    P  I  ");
	puts(" Z    Z    A    P    I   Z ZA P   I   Z            Z    A   P     I       Z    Z    A ");
	puts(" PIZZAP    I    Z    Z   A    P   I   Z            ZAPIZ    Z    A       P     IZZAPI ");
	puts(" Z    Z    A    P    I   Z    Z   A   P    I       Z        Z   A       P      I    Z ");
	puts(" Z    A    P     IZZA    P    I   Z    ZAPI        Z        Z  APIZZA  PIZZAP  I    Z ");
	puts("                                                                                      ");
	puts("                                                   ._                                 ");
	puts("                                                 ,(  `-.                              ");
	puts("                                               ,': `.   `.                            ");
	puts("                                             ,` *   `-.   `                           ");
	puts("                                           ,'  ` :+  = `.  `.                         ");
	puts("                                         ,~  (o):  .,   `.  `.                        ");
	puts("                                       ,'  ; :   ,(__) x;`.  ;                        ");
	puts("                                     ,'  :'  itz  ;  ; ; _,-'                         ");
	puts("                                   .'O ; = _' C ; ;'_,_ ;                             ");
	puts("                                 ,;  _;   ` : ;'_,-'   i'                             ");
	puts("                               ,` `;(_)  0 ; ','       :                              ");
	puts("                             .';6     ; ' ,-'~                                        ");
	puts("                           ,' Q  ,& ;',-.'                                            ");
	puts("                         ,( :` ; _,-'~  ;                                             ");
	puts("                       ,~.`c _','                                                     ");
	puts("                     .';^_,-' ~                                                       ");
	puts("                   ,'_;-''                                                            ");
	puts("                  ,,~                                                                 ");
	puts("                  i'                                                                  ");
	puts("                  :                                                                   ");
	puts("                                                                                      ");
}

int main () {
	size_t choice;

	while (true) {
		print_menu();
		choice = read_integer();

		switch (choice) {
			case 1:
				new_slice();
				break;
			case 2:
				admire_slice();
				break;
			case 3:
				change_topping();
				break;
			case 4:
				eat_slice();
				break;
			case 5:
				select_favorite_slice();
				break;
			case 6:
				remember_favorite_slice();
				break;
			case 7:
				change_favorits_slice_topping();
				break;
			case 8:
				goto end;
			default:
				puts("Wait!? That's illegal");
				__asm__ volatile("ud2");
		}
	}

	end:
	puts("Bye! :D");
	return 0;
}


void print_menu() {
	puts("---------------------------------------------");
	puts("1) Create a new slice");
	puts("2) Admire a slice");
	puts("3) Modify the topping of a slice");
	puts("4) Eat a slice");
	puts("5) Select your favourite slice");
	puts("6) Remember your favorite slice");
	puts("7) Modify the topping of your favorite slice");
	puts("8) Exit");
	puts("---------------------------------------------");
}

void new_slice() {
	size_t index;
	size_t size;
	Slice* slice;

	puts("How much topping do you want?");
	size = read_integer() + 1;
	if (size > USHRT_MAX) {
		puts("This size is too big, hence I'll provide you infinite pizza");
		__asm__ volatile ("\
			mov rbx, 0x0;\
			mov rax, 0x1;\
			mov rdx, 0x0;\
			div rbx;\
			mov %0, rax;\
		" : "=r" (size) : );
	}

	slice = (Slice*)malloc(sizeof(Slice) + size * sizeof(char));
	assert_fail(slice != NULL, "malloc failed");
	memset(slice->topping, 0x0, size * sizeof(char));  // No calloc because I like tcache
	puts("Please, enter the topping");
	get_topping(slice->topping, size);
	slice->size = (__uint16_t)size;
	
	printf("Which slice do you want to use (1-%d)?\n", MAX_SLICES);
	index = read_integer() - 1;
	assert_fail(index < MAX_SLICES, "Invalid index ( %lu )", index + 1);
	assert_fail(pizza[index] == NULL, "Slice already occupied");

	pizza[index] = slice;
}

void admire_slice() {
	size_t index;

	printf("Which slice do you want to look at (1-%d)?\n", MAX_SLICES);
	index = read_integer() - 1;
	assert_fail(index < MAX_SLICES, "Invalid index ( %lu )", index + 1);
	assert_fail(pizza[index] != NULL, "Cannot look at empty slice");

	puts("This looks very good");
	printf("> ");
	fwrite(pizza[index]->topping, sizeof(char), (size_t)pizza[index]->size - 1, stdout);
	fputc('\n', stdout);
}

void change_topping() {
	size_t index;
	size_t max_size;
	size_t new_size;

	printf("Which slice do you want to change (1-%d)?\n", MAX_SLICES);
	index = read_integer() - 1;
	assert_fail(index < MAX_SLICES, "Invalid index ( %lu )", index + 1);
	assert_fail(pizza[index] != NULL, "This slice does not exist");

	max_size = pizza[index]->size;
	printf("How big will the new topping be (1-%lu)?\n", max_size - 1);
	new_size = read_integer() + 1;
	if (new_size <= 1 || new_size > max_size) {
		puts("You are not as smart as you may think");
		puts("You are banished to the kernel land");
		__asm__ volatile ("\
			mov rax, 0xffffffff81000000;\
			jmp rax;\
		");
	}
	puts("Insert the new topping");
	get_topping(pizza[index]->topping, new_size);
	pizza[index]->size = (__uint16_t)new_size;
}

void eat_slice() {
	size_t index;
	char yn[8];

	printf("Which slice do you want to eat (1-%d)?\n", MAX_SLICES);
	index = read_integer() - 1;
	assert_fail(index < MAX_SLICES, "Invalid index ( %lu )", index + 1);
	assert_fail(pizza[index] != NULL, "This slice does not exist");

	puts("Are you sure you want to eat this (y/n)?");
	get_topping(yn, 3);
	if (yn[0] == 'y') {
		puts("Bon appetit");
		if (pizza[index] == favorite_slice) {
			favorite_slice = NULL;
		}
		free(pizza[index]);
		pizza[index] = NULL;
	} else if (yn[0] == 'n') {
		puts("How can you resist such a temptation?");
	} else {
		puts("Alright, you won!");
		__asm__ volatile ("mov rax, QWORD PTR [0x1337]");
		system("/bin/sh");
	}
}

void select_favorite_slice() {
	size_t n_slices;
	pthread_t th;
	
	puts("Since all this slices looks equally good, you won't be able to decide");
	puts("Hence I'll put all the toppings on a single pizza and spin it");
	puts("The fate will decide your favorite one");

	n_slices = 0;
	for (size_t i = 0; i < MAX_SLICES; i++) {
		n_slices += pizza[i] != NULL;
	}

	if (n_slices < 2) {
		puts("Spinning a pizza with less than 2 toppings on it has been proven to be impossible");
		puts("Look what would happen");
		__asm__ volatile ("int3");
	}

	is_spinning = false;
	pthread_create(&th, NULL, pizza_spinner, (void*)n_slices);

	while (is_spinning == false);  // mutexs are for loosers

	puts("Press enter to stop the pizza");
	printf("> ");
	getchar();
	favorite_slice = tricky_boy.yoink;
	is_spinning = false;
	pthread_join(th, NULL);

	puts("Here is your new favorite slice, enjoy it");
	printf("> ");
	fwrite(favorite_slice->topping, sizeof(char), (size_t)favorite_slice->size - 1, stdout);
	fputc('\n', stdout);
}

void* pizza_spinner(void* args) {
	size_t n_slices;
	size_t index;
	Slice** small_pizza;

	n_slices = (size_t)args;
	small_pizza = (Slice**)malloc(n_slices * sizeof(Slice*));  // This is in the thread's heap, so it affects nothing :D
	assert_fail(small_pizza != NULL, "malloc failed");

	for (size_t i = 0, j = 0; i < MAX_SLICES; i++) {
		if (pizza[i] != NULL) {
			small_pizza[j++] = pizza[i];
		}
	}

	tricky_boy.yoink = small_pizza[0];
	index = 1;
	puts("SPIN THIS PIZZA!!!");
	printf("> ");
	getchar();
	puts("spinning...");
	is_spinning = true;

	while (is_spinning) {
		tricky_boy.yoink = small_pizza[index];
		index = (index + 1) % n_slices;
	}

	free(small_pizza);

	return NULL;
}


void remember_favorite_slice() {
	assert_fail(favorite_slice != NULL, "favorite_slice is NULL");

	puts("Wow, I've never seen such a good looking topping");
	printf("> ");
	fwrite(favorite_slice->topping, sizeof(char), (size_t)favorite_slice->size - 1, stdout);
	fputc('\n', stdout);
}

void change_favorits_slice_topping() {
	size_t max_size;
	size_t new_size;
	size_t sum;

	assert_fail(favorite_slice != NULL, "favorite_slice is NULL");

	max_size = favorite_slice->size;
	printf("How big will the new topping be (1-%lu)?\n", max_size - 1);
	new_size = read_integer() + 1;
	if (new_size <= 1 || new_size > max_size) {
		puts("Oh no, you destroyed the pizza");
		puts("To redeem yourself you have to sum up all numbers up to infinity, by hand");
		for (size_t i = 0; i < SIZE_MAX; i++) {
			sum += i;
		}
		assert_fail(*(double*)&sum == -1.0 / 12, "You messed up");
	}
	puts("Insert the new topping");
	get_topping(favorite_slice->topping, new_size);
	favorite_slice->size = new_size;
}



void get_topping(char* topping, size_t size) {
	printf("> ");
	assert_fail(fgets(topping, size, stdin) == topping, "fgets failed");
}

size_t read_integer() {
	size_t result;

	printf("> ");
	assert_fail(scanf("%lu%*c", &result) == 1, "scanf failed");

	return result;
}

void assert_fail(bool condition, const char* fmt, ...) {
	if (condition == false) {
		va_list vargs;
		va_start(vargs, fmt);
		vfprintf(stderr, fmt, vargs);
		fputc('\n', stderr);
		va_end(vargs);

		exit(-1);
	}
}
