#include <stdio.h>
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

int main() {
        int fd = open("/dev/kreapmem0", O_RDWR | O_SYNC);
        if (fd < 0) {
                perror("open");
                return 1;
        } else {
                printf("opened /dev/kreapmem0\n");
        }
        
        int i = 0;
        char buf[512];
        while (read(fd, buf, 512) > 0) {
                printf("Sector %d:\n", i);
                for (int j = 0; j < 512; j++) {
                        printf("%02x", buf[j]);
                }
                puts("");
                i++;
        }

        close(fd);
}