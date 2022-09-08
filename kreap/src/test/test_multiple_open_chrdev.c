#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main() {
    int first = open("/dev/kreapctl", O_RDWR);

    if(first < 0) {
        printf("Error opening device\n");
        return 1;
    }

    printf("Device opened, fd=%d\n", first);

    getchar(); /* Wait for user input */

    int second = open("/dev/kreapctl", O_RDWR);

    if(second < 0) {
        printf("Error opening device: %s\n", strerror(second));
        close(first);
        return 1;
    }

    printf("Device opened, fd=%d\n", second);

    close(second);
    close(first);

    return 0;
}