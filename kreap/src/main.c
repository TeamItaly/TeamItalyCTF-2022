#include <stdio.h>
#include <string.h>

#define __USE_GNU
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>

#define KREAP_DEFAULT_ADDR 0x100000000000
#define KREAP_SECTOR_SIZE 512
static void *mem;
static size_t tot_sectors;
int kreapctl, kreapmem;

#define ceil_div(x, y) (((x) + (y) - 1) / (y))

/* Define command formats */
enum cmds {
	CMD_GET_DISK = 0,
	CMD_MALLOC,
	CMD_FREE
};
struct kreap_cmd {
	enum cmds	id;
	u_int32_t	arg0;
	u_int32_t	arg1;
};
struct kreap_ans {
	int		err;	/* reuse errno errors */
	u_int32_t	arg0;
};

/* Library preload */
__attribute__((constructor)) void kreap_init(void)
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

	sprintf(mempath, "/dev/kreapmem%d", ans.arg0);

	/* wait for the device */
	while (kreapmem <= 0) {
		kreapmem = open(mempath, O_RDWR | O_DSYNC);
	}
}

__attribute__((destructor)) void kreap_fini(void)
{
	close(kreapmem);
	close(kreapctl);
}

static inline size_t min(size_t a, size_t b)
{
	return a < b ? a : b;
}

void *malloc(size_t size)
{
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
		fprintf(stderr, "malloc failed: %s", strerror(ans.err));
		return NULL;
	}

	if (ans.arg0 != tot_sectors) {
		exit(1);
	}

	/* map the memory */
	if (mem == NULL) {
		mem = mmap((void *)KREAP_DEFAULT_ADDR, no_sectors * KREAP_SECTOR_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED_VALIDATE, kreapmem, 0);
		if (mem == MAP_FAILED) {
			exit(1);
		}
	} else {
		mem = mremap(mem, tot_sectors * KREAP_SECTOR_SIZE, (tot_sectors + no_sectors) * KREAP_SECTOR_SIZE, 0);
		if (mem == MAP_FAILED) {
			exit(1);
		}
	}

	/* write the chunk size (in sectors) */
	size_t *ret_mem = (size_t *)((unsigned long)mem + tot_sectors * KREAP_SECTOR_SIZE);
	*ret_mem = no_sectors;

	tot_sectors += no_sectors;

	/* return the wanted address after adding the metadata */
	return &ret_mem[1];
}

void *calloc(size_t nmemb, size_t size)
{
	void *ret = malloc(nmemb * size);
	memset(ret, 0, nmemb * size);
	return ret;
}

void *realloc(void *src, size_t sz)
{
	if (sz == 0) {
		free(src);
		return NULL;
	}
	if (src == NULL) {
		return malloc(sz);
	}

	void *dst = malloc(sz);
	size_t old_sz = ((size_t *)src)[-1];

	memcpy(dst, src, min(old_sz, sz)); /* !! */
	free(src);

	return dst;
}

void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	/* check for multiplication overflow */
	if (nmemb > ULONG_MAX / size) {
		return NULL;
	}
	return realloc(ptr, nmemb * size);
}

void free(void *ptr)
{
	/* C's answer to free(NULL) */
	if (ptr == NULL) {
		return;
	}

	struct kreap_cmd cmd;
	struct kreap_ans ans;
	size_t size = ((size_t *)ptr)[-1];
	size_t offset = (unsigned long)ptr - (unsigned long)mem - 8UL;

	cmd.id = CMD_FREE;
	cmd.arg0 = (u_int32_t)(offset / KREAP_SECTOR_SIZE);	/* offset in sectors */
	cmd.arg1 = (u_int32_t)size;				/* how many nodes to free */

	if (write(kreapctl, &cmd, sizeof(cmd)) < 0) {
		exit(1);
	}
	if (read(kreapctl, &ans, sizeof(ans)) < 0) {
		exit(1);
	}

	/* check for errors */
	if (ans.err) {
		fprintf(stderr, "free failed: %s", strerror(ans.err));
		exit(1);
	}
}

#define ANSI_ESCAPE "\x1b["
#define ANSI_RESET ANSI_ESCAPE "0m"
#define ANSI_RED ANSI_ESCAPE "31m"
#define ANSI_GREEN ANSI_ESCAPE "32m"
#define ANSI_YELLOW ANSI_ESCAPE "33m"
#define ANSI_BLUE ANSI_ESCAPE "34m"

const char banner[] =
ANSI_BLUE
"\n"
"\t██╗  ██╗██████╗ ███████╗ █████╗ ██████╗      ██╗    ██████╗ \n"
"\t██║ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗    ███║   ██╔═████╗\n"
"\t█████╔╝ ██████╔╝█████╗  ███████║██████╔╝    ╚██║   ██║██╔██║\n"
"\t██╔═██╗ ██╔══██╗██╔══╝  ██╔══██║██╔═══╝      ██║   ████╔╝██║\n"
"\t██║  ██╗██║  ██║███████╗██║  ██║██║          ██║██╗╚██████╔╝\n"
"\t╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝          ╚═╝╚═╝ ╚═════╝ \n"
"\n"
ANSI_RESET
"Welcome to my Kreap implementation!\n"
"I am sure you will be stunned by the amount of memory I'm saving here.\n"
"What do you want to do?\n";

const char menu[] =
"  1. Store my really valuable secret (not the flag)\n"
"  2. Store your personal informations\n"
"  3. Read your personal informations\n"
"  4. Read my really valuable secret (not the flag)\n"
"  5. Erase your completely useless (and personal) informations\n"
"  0. Exit\n";

const char prompt[] =
ANSI_GREEN "> " ANSI_RESET;

static inline void ask(const char *str)
{
	puts(str);
	printf(prompt);
}

#define NO_SLOTS (50)
#define NO_SLOTS_STR "50"

static void *allocs[NO_SLOTS];
static char *my_really_valuable_secret;

int main(void)
{
	/* disable buffering */
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	u_int32_t choice, slot;
	size_t str_size;
	char *str;

	printf(banner);

	while (1) {
		printf(menu);
		printf(prompt);

		scanf("%u", &choice);
		switch (choice) {
		/* store my really valuable secret (not the flag) */
		case 1: {
			if (my_really_valuable_secret != NULL) {
				puts("I am lazy, won't read it again :(");
				break;
			}
			FILE *f = fopen("flag.txt", "r");
			getline(&my_really_valuable_secret, &str_size, f);
			fclose(f);
			break;
		}
		/* store your personal informations */
		case 2:
			ask("Choose a slot [0-" NO_SLOTS_STR ")");
			scanf("%u", &slot);
			if (slot >= NO_SLOTS) {
				puts("Invalid slot");
				break;
			}
			if (allocs[slot]) {
				puts("Slot already allocated!");
				break;
			}

			ask("Write something");
			/* read a string */
			str = NULL;
			getchar();
			getline(&str, &str_size, stdin);
			allocs[slot] = str;
			puts("You're welcome");
			break;
		/* read your personal informations */
		case 3:
			ask("Choose a slot [0-" NO_SLOTS_STR ")");
			scanf("%u", &slot);
			if (slot >= NO_SLOTS) {
				puts("Invalid slot");
				break;
			}
			if (!allocs[slot]) {
				puts("Slot not allocated!");
				break;
			}
			printf("%s", (char *)allocs[slot]);
			break;
		/* read my really valuable secret (not the flag) */
		case 4:
			printf("Here you go: %p\n", (void *)&my_really_valuable_secret);
			break;
		/* erase your completely useless (and personal) informations */
		case 5:
			ask("Choose a slot [0-" NO_SLOTS_STR ")");
			scanf("%u", &slot);
			if (slot >= NO_SLOTS) {
				puts("Invalid slot");
				break;
			}
			if (!allocs[slot]) {
				puts("Slot not allocated!");
				break;
			}
			free(allocs[slot]);
			allocs[slot] = NULL;
			break;
		case 0:
			exit(0);
			break;
		default:
			puts("Invalid choice");
			break;
		}
		/*
		 * uncomment to get an easier flagging
		 * msync(mem, KREAP_SECTOR_SIZE * tot_sectors, MS_SYNC);
		 */
	}
}
