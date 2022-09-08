#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <errno.h>

#ifdef DEBUG
#define DBG 
#else
#define DBG if (false) 
#endif

struct item {
    char id[32];
    char token[32];
    char* description;
    unsigned int price;
};

struct item* currentItem;
unsigned int bal = 20000;
int dirFd;
int fd;

void banner() {
    char string[] = "                                                 _|                                                        \n"
                    " _|      _|                      _|            _|                                                          \n"
                    " _|_|  _|_|    _|_|_|  _|  _|_|        _|_|        _|_|_|                                                  \n"
                    " _|  _|  _|  _|    _|  _|_|      _|  _|    _|    _|_|                                                      \n"
                    " _|      _|  _|    _|  _|        _|  _|    _|        _|_|                                                  \n"
                    " _|      _|    _|_|_|  _|        _|    _|_|      _|_|_|                                                  \n\n"
                    " _|      _|              _|                                                                                \n"
                    " _|_|  _|_|    _|_|    _|_|_|_|    _|_|_|  _|      _|    _|_|    _|  _|_|    _|_|_|    _|_|                \n"
                    " _|  _|  _|  _|_|_|_|    _|      _|    _|  _|      _|  _|_|_|_|  _|_|      _|_|      _|_|_|_|              \n"
                    " _|      _|  _|          _|      _|    _|    _|  _|    _|        _|            _|_|  _|                    \n"
                    " _|      _|    _|_|_|      _|_|    _|_|_|      _|        _|_|_|  _|        _|_|_|      _|_|_|            \n\n"
                    " _|      _|                      _|                    _|                _|                                \n"
                    " _|_|  _|_|    _|_|_|  _|  _|_|  _|  _|      _|_|    _|_|_|_|  _|_|_|    _|    _|_|_|    _|_|_|    _|_|    \n"
                    " _|  _|  _|  _|    _|  _|_|      _|_|      _|_|_|_|    _|      _|    _|  _|  _|    _|  _|        _|_|_|_|  \n"
                    " _|      _|  _|    _|  _|        _|  _|    _|          _|      _|    _|  _|  _|    _|  _|        _|        \n"
                    " _|      _|    _|_|_|  _|        _|    _|    _|_|_|      _|_|  _|_|_|    _|    _|_|_|    _|_|_|    _|_|_|  \n"
                    "                                                               _|                                          \n"
                    "                                                               _|                                          ";

    puts(string);
}

void initialize() {
    srand(time(NULL));
    
    chroot(".");
    if (getuid() == 0) {
        if (setgid(1000) != 0)
            exit(3);
        if (setuid(1000) != 0)
            exit(3);
        if (setegid(1000) != 0)
            exit(3);
        if (seteuid(1000) != 0)
            exit(3);
    }

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    banner();
    dirFd = open(".", O_DIRECTORY, 0700);
}

void rand_string(char *buf, size_t size) {
    for (int i = 0; i < size; ++i) {
        unsigned int randomChar = rand()%(26+26+10);       
        if (randomChar < 26)
            buf[i] += 'a' + randomChar;
        else if (randomChar < 26+26)
            buf[i] += 'A' + randomChar - 26;
        else
            buf[i] += '0' + randomChar - 26 - 26;
    }
    DBG printf("rand: %s\n", buf);
}

void validateToken() {
    puts("Enter token: ");
    char in[33];
    fgets(in, 33, stdin);
    getchar();
    if (strncmp(in, currentItem->token, 32) != 0) {
        puts("Token invalid");
        DBG printf("correct was %s\n", currentItem->token);
        exit(1);
    }
}

void itemInfo() {
    char form[] =   "|\t Item ID: %s \n"
                    "|\t Item secret token: %s \n"
                    "|\t Item price: %u \n"
                    "|\t Item description: \n\t\t %s \n"
                    "--------------------------------------\n\n";
    char id[33];
    char tok[33];
    memset(id, 0, 33);
    memset(tok, 0, 33);
    memcpy(id, currentItem->id, 32);
    memcpy(tok, currentItem->token, 32);
    printf(form, id, tok, currentItem->price, currentItem->description);
}

void saveItem(bool open) { // maybe do error handling here
    if (!open) {
        char id[33];
        memset(id, 0, 33);
        strncpy(id, currentItem->id, 32);
        fd = openat(dirFd, id, 0 | O_RDWR | O_CREAT, 0660);
    }
    lseek(fd, 0, SEEK_SET);
    write(fd, currentItem->token, 32);
    write(fd, &currentItem->price, 4);
    write(fd, currentItem->description, strlen(currentItem->description));
    if (!open) {
        close(fd);
        fd = 0;
    }
    itemInfo();
}

// long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size) {
//     return syscall(SYS_openat2, dirfd,pathname, how, size);
// }

bool loadItem(char* id, bool trusted) {
    if (faccessat(dirFd, id, F_OK | R_OK, 0 ) != 0) {
        printf("Item %s does not exist.\n\n", id);
        return false;
    }

    // maybe openat2 here, if i don't do path traversal prevention anywhere else 
    fd = openat(dirFd, id, O_RDONLY); // O_DIRECT needs special alignment, figure that out
    // lseek(fd, 0, SEEK_SET); // this isn't really needed
    // if (fd < 0)
    //     goto fail;

    char tmp[32] = "AAAAA";

    int s = read(fd, tmp, 32);
    

    DBG puts(tmp);
    DBG printf("  %d\n", s);
    if (s <= 0)
        goto fail;

    struct stat st;
    stat(id, &st);
    off_t size = st.st_size;

    char* ptrDesc = malloc(size - 36);
    currentItem = malloc(sizeof(struct item));
    
    currentItem->description = ptrDesc;
    memcpy(currentItem->id, id, 32);
    memcpy(currentItem->token, tmp, 32);

    if (!trusted) {
        validateToken();
        close(fd);
        fd = openat(dirFd, id, 0 | O_RDWR, 0660);
    }

    lseek(fd, 32, SEEK_SET);

    if (read(fd, &currentItem->price, 4) == NULL)
        goto fail;

    int fpos = lseek(fd, 0, SEEK_CUR);
    int fend = lseek(fd, 0, SEEK_END);
    lseek(fd, fpos, SEEK_SET);


    if (read(fd, ptrDesc, fend - fpos) == NULL)
        goto fail;

    if (trusted) {
        close(fd);
        fd = openat(dirFd, id, 0 | O_RDWR, 0660);
    }

    itemInfo();
    return true;

fail:
    puts("Cannot load item. You can send a complaint email at /dev/null\n");
    DBG printf("%d %s\n", errno, strerror(errno));
    exit(1);
}

void loadItemMenu() {
    puts("\nEnter item ID: ");
    
    char in[33];
    fgets(in, 33, stdin);
    getchar();
    // check here if input is in allowed charset?
    if(loadItem(in, false)) {
        while (true) {
            char string[] = "\t 1. Edit price \n"
                            "\t 2. Edit description \n"
                            "\t 3. Save item \n"
                            "\t 4. Undo changes \n"
                            "\t 0. Exit \n";
            puts(string);
            puts("\nMake your selection: ");
            int sel = getchar();
            getchar();
            switch(sel) {
                case 0x30:
                    return;
                case 0x31:
                    puts("Insert new price: ");
                    scanf("%u", &currentItem->price);
                    break;
                case 0x32:
                    char tmp[1024];
                    memset(tmp, 0, 1024);
                    puts("Insert new description (up to 1023 characters): ");
                    fgets(tmp, 1023, stdin);
                    int len = strlen(tmp);
                    currentItem->description = realloc(currentItem->description, len);
                    if (currentItem->description == NULL) {
                        printf("Error reallocating memory\n");
                        exit(2);
                    }
                    memcpy(currentItem->description, tmp, len);
                    break;
                case 0x33:
                    saveItem(true);
                    break;
                case 0x34:
                    char o[33];
                    strncpy(o, currentItem->id, 32);
                    o[32] = 0;
                    loadItem(o, true);
                    break;
                default:
            }
        }
    }
}

void menu() {
    char string[] = "\t 1. Create New Item \n"
                    "\t 2. Edit Existing Item \n"
                    "\t 0. Exit \n";
    puts(string);
    puts("\nMake your selection: ");
    int sel = getchar();
    getchar();
    switch(sel) {
        case 0x30:
            exit(0);
        case 0x31:
            currentItem = malloc(sizeof(struct item));
            puts("--------------------------------------");
            puts("Insert item price: ");
            scanf("%u", &currentItem->price);
            getchar();
            char tmp[1024];
            memset(tmp, 0, 1024);
            puts("Insert description (up to 1023 characters): ");
            fgets(tmp, 1023, stdin);
            int len = strlen(tmp);
            currentItem->description = malloc(len-1);
            if (currentItem->description == NULL) {
                printf("Error allocating memory\n");
                exit(2);
            }
            memcpy(currentItem->description, tmp, len-1);
            rand_string(&currentItem->id, 32);
            rand_string(&currentItem->token, 32);
            puts("--------------------------------------");
            saveItem(false);
            break;
        case 0x32:
            loadItemMenu();
            break;
        default:
            return;
    }
}

int main() {
    initialize();
    while (true) {
        menu();
    }
}