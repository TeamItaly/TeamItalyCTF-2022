#include <stdio.h>
#include <string.h>
#include "libreap.h"

#define __USE_GNU
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>

#include <assert.h>

#define UREAP_DEFAULT_ADDR 0x100000000000
#define KREAP_SECTOR_SIZE 512
static void *mem;
static size_t tot_sectors;
int kreapctl, kreapmem;

/* Library preload */
__attribute__((constructor)) void ureap_init(void)
{
	struct kreap_cmd cmd;
	struct kreap_ans ans;
	char mempath[32];

	/* open the control device */
	kreapctl = open("/dev/kreapctl", O_RDWR);
	if (kreapctl < 0) {
		exit(1);
	}

	/* ask for a disk */
	cmd.id = CMD_GET_DISK;
	if (write(kreapctl, &cmd, sizeof(cmd)) < 0) {
		exit(1);
	}
	if (read(kreapctl, &ans, sizeof(ans)) < 0) {
		exit(1);
	}

	if (ans.err != 0) {
		exit(1);
	}

	/* wait for the device */
	sprintf(mempath, "/dev/kreapmem%d", ans.arg0);
	
	/* TODO: quick fix for udev not setting permissions :( */
	while(kreapmem <= 0) {
		kreapmem = open(mempath, O_RDWR | O_DIRECT | O_SYNC | O_DSYNC);
	}
}

__attribute__((destructor)) void ureap_fini(void)
{
	close(kreapmem);
	close(kreapctl);
}

size_t min(size_t a, size_t b)
{
	return a < b ? a : b;
}

/* TODO: we can keep the size in the kernel or in a hash table */
/* TODO: posso mmappare non fixed e farlo per ogni allocazione */
/* TODO: per MAP_SYNC serve DAX */
/* But this opens the door to underflow attacks */
void *malloc(size_t size) {
	struct kreap_cmd cmd;
	struct kreap_ans ans;
	size_t no_sectors;

	/* add the metadata size */
	size += 8ULL;
	/* calculate the number of sectors */
	no_sectors = ceil_div(size, KREAP_SECTOR_SIZE);

	/* ask for a malloc */
	cmd.id = CMD_MALLOC;
	cmd.arg0 = no_sectors;
	if (write(kreapctl, &cmd, sizeof(cmd)) < 0) {
		exit(1);
	}
	if (read(kreapctl, &ans, sizeof(ans)) < 0) {
		exit(1);
	}

	/* check for errors */
	if (ans.err) {
		return NULL;
	}

	// __asm__("int3");
	assert(ans.arg0 == tot_sectors);

	/* map the memory */
	if (mem == NULL) {
		mem = mmap((void *)UREAP_DEFAULT_ADDR, no_sectors * KREAP_SECTOR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kreapmem, 0);
		if (mem == MAP_FAILED) {
			exit(1);
		}
	}
	/* TODO: we can do a mmap for each malloc using offset */
	else {
		mem = mremap(mem, tot_sectors * KREAP_SECTOR_SIZE, (tot_sectors + no_sectors) * KREAP_SECTOR_SIZE, 0);
		if (mem == MAP_FAILED) {
			exit(1);
		}
	}

	/* write the chunk size (in sectors) */
	size_t *ret_mem = mem + tot_sectors * KREAP_SECTOR_SIZE;
	*ret_mem = no_sectors;

	tot_sectors += no_sectors;

	/* return the wanted address after adding the metadata */
	return &ret_mem[1];
}

void *calloc(size_t nmemb, size_t size) {
	void *ret = malloc(nmemb * size);
	memset(ret, 0, nmemb * size);
	return ret;
}

/* TODO: puoi aggiungere un bug qui se non controlli la size mentre copi i dati */
void *realloc(void *src, size_t sz) {
	if (sz == 0) {
		free(src);
		return NULL;
	}
	if (src == NULL) {
		return malloc(sz);
	}

	void *dst = malloc(sz);
	size_t old_sz = ((size_t *)src)[-1];

	printf("realloc: sz copied: %zu\n", min(old_sz * KREAP_SECTOR_SIZE, sz));

	// BUG: here it's old_sz * KREAP_SECTOR_SIZE
	memcpy(dst, src, min(old_sz * KREAP_SECTOR_SIZE, sz));
	free(src);

	return dst;
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
	/* check for multiplication overflow */
	if (nmemb > ULONG_MAX / size) {
		return NULL;
	}
	return realloc(ptr, nmemb * size);
}

void free(void *ptr) {
	/* C's answer to free(NULL) */
	if (ptr == NULL) {
		return;
	}

	struct kreap_cmd cmd;
	struct kreap_ans ans;
	size_t size = ((size_t *)ptr)[-1];
	size_t offset = ptr - mem - 8;

	cmd.id = CMD_FREE;
	cmd.arg0 = offset / KREAP_SECTOR_SIZE;		/* offset in sectors */
	cmd.arg1 = size;	/* how many nodes to free (TODO: move to the module) */

	if (write(kreapctl, &cmd, sizeof(cmd)) < 0) {
		exit(1);
	}
	if (read(kreapctl, &ans, sizeof(ans)) < 0) {
		exit(1);
	}

	/* check for errors */
	if (ans.err) {
		exit(1);
	}
}

static void *(allocated[1024]);

// To fix race conditions: sync before free/malloc
// disable buffering TODO: you can leave it on to make it more difficult(?)
// SOL: with getline you can allocate 2^n sectors (120*4 = 480) -> allocate 2^n - 1 + single sector
// but still a large amount gets freed
// TODO: i can fix realloc to not free and the allocate again if i'm at the end of the trheap
// TODO: find a way to not use 8 bytes and alloc a new sector when allocating large powers of 2 bytes
// but if I put that size in the kreap I would have another vuln if I free a wrong node
// we can use a hash table in the kernel perhaps
// and not free anything if we don't find the hash table in the kernel
// then try to fix the race condition if it exists
/* TODO: *warning* memalign, aligned_alloc, pvalloc, valloc missing */
/* Testing only, no safety checks */
/*int main() {
	int choice, sz, slot = 0, slot_choice;

	while(1) {
		puts("Allocator v3ULL:\n"
			"1. Allocate\n"
			"2. Free\n"
			"3. Write\n"
			"4. Read\n"
			"5. Exit"
		);
		scanf("%d", &choice);
		switch(choice) {
			case 1:
				puts("Choose size (in sectors): ");
				scanf("%d", &sz);
				allocated[slot++] = malloc(sz * KREAP_SECTOR_SIZE - 8);
				printf("Alloc slot: %d (%p)\n", slot - 1, allocated[slot - 1]);
				break;
			case 2:
				puts("Choose slot: ");
				scanf("%d", &slot_choice);
				free(allocated[slot_choice]);
				allocated[slot_choice] = NULL;
				break;
			case 3:
				puts("Choose slot: ");
				scanf("%d", &slot_choice);
				puts("How many bytes? ");
				scanf("%d", &sz);
				memset(allocated[slot_choice], 0x2a, sz);
				break;
			case 4:
				puts("Choose slot: ");
				scanf("%d", &slot_choice);
				puts("How many bytes? ");
				scanf("%d", &sz);
				for (int i = 0; i < sz; i++) {
					printf("%2hhx", ((char *)allocated[slot_choice])[i]);
				}
				puts("");
				break;
			case 5:
				exit(0);
				break;
			default:
				puts("Invalid choice");
				break;
		}
	}
}*/

/* oldmain debug */
// /* debug, read sector */
// case 6:
// 	ask("Choose a sector");
// 	scanf("%u", &size);
// 	printf("reading: %p\n", mem + size * KREAP_SECTOR_SIZE);
// 	for (int i = 0; i < 50; i++) {
// 		printf("%c", *(char *)(mem + size * KREAP_SECTOR_SIZE + i));
// 	}
// 	break;
// /* debug, allocate sector */
// case 7:
// 	ask("Choose a slot");
// 	scanf("%u", &slot);
// 	ask("How many sectors?");
// 	scanf("%u", &size);
// 	allocs[slot] = malloc(size * KREAP_SECTOR_SIZE - 8);
// 	break;
// /* debug, free sector */
// case 8:
// 	ask("Choose a slot");
// 	scanf("%u", &slot);
// 	if (!allocs[slot]) {
// 		puts("Slot not allocated!");
// 		break;
// 	}
// 	free(allocs[slot]);
// 	allocs[slot] = NULL;
// 	break;

// /* TODO: debug */
// fsync(kreapmem);
// msync(mem, KREAP_SECTOR_SIZE * tot_sectors, MS_SYNC);

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	char *buf = malloc(100);
	memset(buf, 0x2a, 100);
	buf[99] = 0;

	buf = realloc(buf, 200);
	printf("%s\n", buf);

	getchar();

	printf("%s\n", buf);
}
