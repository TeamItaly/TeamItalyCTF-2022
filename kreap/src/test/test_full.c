#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

/* kreapctl.c */
enum cmd_ids {
	CMD_GET_DISK = 0,
	CMD_MALLOC,
	CMD_FREE,
	CMD_CALLOC,
	CMD_REALLOC,
	CMD_REALLOC_ARRAY
};

struct kreap_cmd {
	enum cmd_ids    id;
	int64_t         arg0;
	int64_t         arg1;
	int64_t         arg2;
};

struct kreap_ans {
	int     err;
	int64_t arg0;
};

int main() {
    /* Open */
    int ctl = open("/dev/kreapctl", O_RDWR);
    if (ctl < 0) {
        perror("open");
        return 1;
    } else {
        printf("opened /dev/kreapctl\n");
    }

    /* Ask for a disk */
    struct kreap_cmd cmd;
    cmd.id = CMD_GET_DISK;

    if (write(ctl, &cmd, sizeof(cmd)) < 0) {
        perror("write");
        return 1;
    } else {
        printf("sent CMD_GET_DISK\n");
    }

    /* Wait for the answer */
    struct kreap_ans ans;
    if (read(ctl, &ans, sizeof(ans)) < 0) {
        perror("read");
        return 1;
    } else {
        printf("got answer %d\n", ans.err);
    }

    getchar();

    /* Open the disk */
    char path[256];
    snprintf(path, sizeof(path), "/dev/kreapmem%d", ans.arg0);
    int disk = open(path, O_RDWR);

    if (disk < 0) {
        perror("open");
        return 1;
    } else {
        printf("opened %s\n", path);
    }

    /* Ask for a malloc */
    cmd.id = CMD_MALLOC;
    cmd.arg0 = 0x1000;

    if (write(ctl, &cmd, sizeof(cmd)) < 0) {
        perror("write");
        return 1;
    } else {
        printf("sent CMD_MALLOC\n");
    }
    if (read(ctl, &ans, sizeof(ans)) < 0) {
        perror("read");
        return 1;
    } else {
        printf("got answer %d: %s\n", ans.err, strerror(ans.err));
        printf("offset = %ld\n", ans.arg0);
    }


    /* mmap the disk */
    void *disk_mem = mmap((void *)0x10000000ll, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, disk, 0);

    if (disk_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    } else {
        printf("mmapped %s\n", path);
        printf("disk_mem = %p\n", disk_mem);
    }

    getchar();

    char *buf = disk_mem + ans.arg0 * 512;

    /* Write something to the disk */
    memset(buf, 'A', 0x1000);

    /* Read it back */
    printf("%c\n", *buf);

    /* Ask for a free */
    // Not yet implemented

    /* Close everything */
    munmap(disk_mem, 0x10000000ll);
    close(disk);
    close(ctl);
}