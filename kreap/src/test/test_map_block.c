#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>

int main() {
    int fd = open("/dev/nvme0n1p9", O_RDONLY);

    if(fd < 0) {
        printf("Error opening device\n");
        return 1;
    }

    void* addr = mmap(NULL, 1024ll * 1024ll * 1024ll * 50, PROT_READ, MAP_SHARED, fd, 0);

    if(addr == MAP_FAILED) {
        printf("Error mapping device\n");
        return 1;
    }

    for (long long i = 0; i < 1024ll / 8ll * 1024ll * 1024ll * 50; ++i) {
        printf("%llx: %llx \n", i, ((long long*)addr)[i]);
    }
}