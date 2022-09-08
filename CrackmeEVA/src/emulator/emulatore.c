#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define CACHESIZE 100
#define clearscreen() printf("\e[1;1H\e[2J")

typedef struct {
    char reg1;
    char reg2;
    char reg3;
    char reg4;
    char reg5;
    char flag;
    char * data_ptr;
    char * ro_data_ptr;
    char * IP;
} registers;

typedef struct {
    char * code;
    char * ro_data;
    char * data;
    unsigned int code_len;
    unsigned int ro_data_len;
    unsigned int data_len;
    registers reg;
} virtual_machine;

typedef struct {
    int i; 
    char * cache[CACHESIZE];
} cache;

// Keep the stack like that to allow the overflow
typedef struct {
    char *tmp1, *tmp2;
    cache c;
} stack;

// will be patched by python
char * evildata = "\xd7\xa4\x9\xe4\x1c\xc\x61\xbf\xbc\x25\xb\xb1\xd4\x1c\x87\xeb\xd8\x14\x9f\xd6\xf3\xae\xbf\xf6\x4a\x7\xfa\xa9\x64\xfd\x1c\x50\xe5\xe1\xf7\x3\xce\x6\xba\x20\xdd\x6c\x25\x71\xd0\xc6\x98\x5e\xb9\x5a\xc1\x45\x4e\x0\x56\x6b\x8b\x43\xa6\x97\xab\x78\x90\xca\x60\x51\x2e\x43\xed\x83\xd2\x40\xfb\x4\x63\x65\x46\x60\xc\xac\x13\xeb\xd3\x50\xc2\x84\x67\x15\x36\x90\xf0\x71\xc7\x6d\x1a\x18\x3f\x9d\x37\x59\x76\x5d\xbf\x54\xe\x6b\xb0\xca\xef\xad\x2e\xb3\xfb\x9e\x6\x80\x9c\x3a\x56\x1e\x2b\xc9\x69\xae\x52\xc3\xf8\x94\x8\x62\x8c\xfe\x2b\x32\xc6\xca\x36\x91\x79\x3\xcc\x4a\x54\xd8\xe6\x2d\xb\x19\x4e\x99\xe1\xd3\xf7\xf7\xc8\x18\x33\x29\x98\xcb\x1e\xe3\x4e\x70\xa6\xd\x13\xf5\x68\x71\xcf\xb3\x4e\x18\xf7\x37\x35\x46\x8d\xd5\x5b\xef\x60\xec\x4e\x22\x0\xc1\x41\x16\xfb\xf2\x29\xb0\xeb\x9a\xc\x6f\x58\xf7\x9d\xd8\xa3\xce\xdd\xde\xba\x2\x87\x38\x45\xc7\xec\x52\xdc\x85\x18\xbe\xbc\x1a\x47\x6d\xf2\x10\x23\xf7\x32\x3d\xed\xd5\xe8\xb1\xaf\x7c\x41\x81\xde\x72\xd2\x8d\x2a\xdf\xaf\xd5\xc1\x21\x2f\x48\x9a\x6e\x27\xc1\xd8\xe5\xc7\x9c\x27\x5b\x0\x7a\x53\x8a\xe\xde\x17\x2a\xbc\x98\xa8\x82\x9e\xdb\x54\xaa\xfd\xd0\xe0\x45\xcd\xe1\xec\x33\x6d\xdc\x9c\x8f\xd3\x6a\x49\x28\xf2\x72\x9c\x56\x55\x1d\xc0\x90\xeb\xf6\xc4\x4c\x38\x8f\xd0\xd3\x69\xf3\x8b\x94\xa2\x89\x23\x8b\xf8\xeb\xd\xc7\x62\xdb\x21\x84\x81\x52\x9\x2e\x9f\x66\xa4\xd8\xbe\x6f\x58\xcb\x88\xcc\x41\xb9\x77\xd\x78\x43\xe5\x1b\x9c\x35\xba\x91\x38\xb5\xb7\x88\xc7\xbf\x1e\xe3\x5a\xd9\x15\xa4\x6b\xc7\x33\xe7\x51\xb5\xc5\xb\x8a\xf\x7\xbb\x1d\x79\x20\x88\x35\x31\x62\x99\x8d\x16\xc3\x83\x72\x4\xb3\x8b\x28\x24\xe5\x49\xc\xc0\x4a\x94\xad\x84\xe8\xb2\x72\x45\xf0\x1b\xe5\xb4\xfe\x14\x5f\x4a\x3e\xba\x71\xfb\x41\xb0\x2f\xd6\xb9\x20\xc1\xe2\x69\xae\x57\xd\x8f\xc6\x3c\x4c\xe9\x2\x99\x85\x83\x8c\x10\xc5\x49\x90\x24\x24\x46\x2d\x11\xed\x11\x3e\x18\xc2\xf\xa3\xd\xab\x7e\x95\x73\xb3\xfe\x83\x24\x73\x6d\x3b\xc6\x4d\xe1\x6a\xcc\x32\x44\x3d\x34\x84\x8f\x48\xe1\x5a\x2\xfa\xff\xac\x6\x54\xd8\x5b\x8c\xa\x7e\xa4\xce\xd1\xed\xfa\xd2\x81\x87\x12\xef\xc7\xc5\x4a\xbc\xb4\x8a\x48\x70\xde\xb3\xb7\xfa\xda\x3d\xcc\xf7\xce\x4f\xbf\xf4\x27\x24\x61\x8b\x6\x91\x65\xb4\x4f\x22\x4f\x6d\x84\xc1\x9d\x24\x8f\xd2\x2f\x3e\x8\xa7\x56\x3d\x6b\xb3\x38\xc1\x10\x5\x84\x2f\xb4\x9e\xeb\x57\x91\x4c\x5c\x94\xaa\x49\x44\x32\x59\x46\x1\xf0\x78\x6b\x89\x1b\xb1\x96\xc4\x4c\x8\x74\xc9\xd\xbd\x7\xd5\xd3\x6e\x2a\x5\x8f\x6f\xfc\x69\x1a\x27\xe4\x38\xdc\x9a\x33\x22\xe1\x95\xd7\xd4\xf8\x92\xe1\x68\x13\xc4\x59\x62\xbd\x3b\xc4\x45\x1b\x3b\x84\xd6\xbd\xc9\xaf\xa9\x22\xb0\x9a\x57\x32\xf0\x92\xbd\x1b\xa4\x2a\xe3\x91\x92\xbf\x29\xb\x37\x36\x4f\x29\x74\x5a\x64\x32\x6d\x3c\x76\x3\x5a\x6a\x35\xd3\x6e\x66\xfc\x41\x3d\x14\x46\xd\x75\xe9\xc5\x53\xd6\x81\xff\x3b\x74\x1f\xfb\xc0\xf2\xca\x7b\x53\xbb\xd0\x84\x46\xa9\x5f\x4d\x57\x94\x8c\xc4\x5d\x95\x66\x84\xa5\x7\x38\x8d\x69\x54\xf9\x41\xf\x3\xdb\xa5\xc4\x20\x1e\x45\x12\xc7\x48\x3b\x3b\x82\xe6\x27\x5\xea\xcd\xd7\xff\x7e\x62\x58\x75\xef\xd\x18\x48\xb6\xf3\xb2\xf5\x5e\x31\xf2\x46\x38\x14\xb2\x52\x5c\x2d\xdd\x72\xb9\xa\xde\xc5\x7\x99\x3a\xa1\x3c\xc\xb0\xba\x48\xd8\x71\x11\x32\xa0\xca\x15\x69\xac\xc5\xed\x74\xb\x41\x16\x49\x50\x2d\x3c\x72\xee\x4d\xbd\x87\x3f\xee\x59\xa6\x1c\xa0\x81\xf2\x4\xc7\x73\xab\x2d\x67\x99\x31\xbf\x9\xef\xc8\x5\xfd\x71\x24\xab\xf4\x31\x30\xc9\x90\x13\xc6\x94\x11\x4a\x90\x80\x78\x43\xa5\xe1\x12\x2d\xc6\xb6\x4b\x11\x3a\xaa\xe\xa5\x6b\x2b\xe4\xe3\xa2\x36\xd1\xeb\x33\xd9\x25\x87\x45\x9b\xe6\x35\x50\xac\x65\xc9\xb\xbb\x22\xfb\xab\x7b\xb2\xd6\x56\x7c\xb5\xf9\x9a\xce\x96\x40\x90\x5d\x7b\x34\x0\x77\x20\x88\xbc\xc0\x41\xd5\xb8\x7d\x45\x17\xf7\xd\x8e\xee\xac\x5\xb0\x6c\x96\xa8\x74\x23\x7f\xa7\xe4\x8c\x39\xcd\x17\x53\x13\xba\xb\xbd\x87\xba\x67\x2b\xc3\x45\xb\x7b\x77\xe7\xd1\xff\x9\x0\x78\xc5\xc4\x7c\x1\x15\xa4\x7\x18\x84\x61\x14\x46\x22\xbf\xc4\x54\x45\x4c\x39\xad\x15\x16\xe3\xb5\x74\x21\xe8\x58\x56\xde\x4f\xd9\xc7\xe8\x2e\x46\xf4\x39\x8a\x1c\x7b\x1e\x8f\xf\xe8\x6b\x1b\x4a\x1d\x9f\x5f\x49\xfb\xc0\xe3\x4a\x90\xa3\xd4\xb8\xd1\xe\xe7\xab\x7f\xe7\x83\xc9\x5b\xf9\x16\x9e\xe0\x4c\x1c\xaf\x9a\x20\x78\xbc\x9e\x2\xa2\x9f\xa1\xdd\x9a\x21\x4a\x80\x64\xcf\x52\x71\xcc\xfa\xb5\x18\xe8\x6a\x14\x74\xfb\xf2\x45\xaf\x8b\x2d\x50\x15\xdd\x6d\xd9\xa9\x9b\x88\x89\x28\x8e\xe1\x14\xca\x7b\xec\x9\xdf\x8f\x8c\x7d\xd7\x40\x72\xb1\x23\x51\x64\x19\x46\x94\x9\xe4\xe7\x7d\x89\x8f\x83\x7b\x8f\xe4\xbb\xb5\xc2\x7\x75\x5c\xfd\xcd\x8f\xce\x29\xe0\x28\xc5\xe7\xc\x53\x8d\x24\xb4\xf1\xe7\x8f\xb5\x0\x1e\xcc\xe2\x97\xd9\x99\x44\xde\x85\x23\x24\x35\x32\xc3\x50\x15\x48\x8\x1f\x87\xce\xfd\x46\x26\xf\x17\x12\xc0\xbd\xc8\x74\xea\xcf\x71\x6d\x32\x71\x7\xf8\x9e\xe5\x85\xba\x53\xa3\x6c\x2\xdf\xc1\x9\xb3\x95\x4d\xd7\x2e\x9\xa7\x68\x8f\xeb\x53\xe6\xe8\x48\xaa\x4\x41\xd6\x85\x4c\x55\x8b\xbd\x83\xea\xf6\xfe\xff\xfe\xd8\xe\xa4\x93\xd5\xc7\x72\x7b\xd4\xc8\x84\x21\x98\x13\x2c\xce\x69\x33\x73\xec\x11\xd9\xfa\x8c\x32\x37\xe1\x3b\x7c\x2a\x6\x89\xdd\xde\x3d\x5f\x3f\x88\x2c\x2e\xb9\xda\x52\x42\x2\xee\xe1\x6d\x2f\xe5\x2f\xff\xc4\x99\xa4\x79\xec\x29\x60\x67\x48\x9b\x1b\xc2\x9e\x52\x2f\x4\x2a\xd6\x97\xb2\xa5\x96\x4c\x33\x54\x36\x59\x5b\xf\x6\xc3\x2e\x98\x7e\xa9\x5c\x35\xd4\xa\x57\x17\x6e\x1e\xe0\x96\x6\x9b\x86\x41\xcb\x14\xfe\xcc\x16\x26\xc9\x9c\x4\x59\xd3\x3\x73\xf3\x35\x8b\x40\xf0\x44\xb4\x3a\x28\x9\xf0\x2c\x27\xc8\x34\x4\x20\xb4\xfd\xf0\x2e\x58\x7e\x6e\x95\xd6\xf5\x51\xf0\x6b\xc2\xe3\xcb\x1d\xf9\x23\xfb\xcb\x36\xab\xc0\x7f\x75\xa7\x23\xc9\x83\xf\x50\x20\x66\x1f\x36\x8\x73\x8a\x60\x98\x53\x96\xec\xe7\xa8\xd3\x1b\xe0\xa2\x59\xca\xad\x59\x4\x6\x43\xc5\x3e\x38\x33\x51\xf0\xde\x78\x5\xa2\xd3\xad\x40\x26\x51\xe1\xca\x2f\xce\x63\x1\x2a\x6e\x44\xd7\x12\xc4\x1c\xfc\xc6\x6a\x43\xfe\x17\x43\xfa\xad\xab\x1\x8b\xd0\xb4\x7a\xbd\x6b\x73\x48\xf6\x92\xb0\x45\x7f\xd\x35\x2\xaf\x14\x99\xdb\x10\x12\x63\x30\x9e\xe4\x5f\x71\xda\x7e\x9b\x53\x34\xe6\x45\x88\x93\x7d\xc5\xcf\xb6\x6e\x23\x29\x80\x53\x79\x90\x1d\x9f\x14\x59\x16\x4b\x85\x84\x42\xbe\xfc\x21\x28\xef\x26\x8\x57\xa5\x94\xc4\xfb\xd3\xa4\xaa\x1c\x39\xa9\xc4\x39\x5\xef\xd0\xfc\xc1\xba\x46\x81\x76\x8e\x4c\xbd\x35\xa3\x62\x49\x3\x38\xb5\x1f\xe4\x18\xc3\x97\x62\xcd\x86\xd5\x71\xe1\xbb\xed\x10\xce\xe2\xe\xe5\x96\x42\x18\x70\x3e\x86\xc3\x8f\x75\xdf\x6\xf4\xd0\x39\x9f\xb3\xfe\xaf\x3f\x89\x77\xef\x90\x69\x4e\x96\x3a\xb9\xde\xd\x4a\x26\x4e\x1e\xa4\xfe\x14\x28\x98\xc5\x60\xbd\x35\x86\x74\x8d\xdc\x8d\x8a\xb1\x80\x65\xf7\x50\x8b\xa8\x5f\xc0\x8f\x9c\xf6\xe8\x37\xeb\x39\xb8\xda\x8d\xe7\x37\x6\x69\x4f\xe1\xdd\x90\xe\x59\xaf\xb9\x12\x1e\x25\x6d\x74\x10\xcf\x37\xcb\xe4\x1e\xc0\x81\xd4\x18\x99\x3f\x91\xb6\xb4\x67\x36\x6b\xfb\x90\xdc\xe\xa3\xe0\x11\xa8\x37\xbf\xef\x90\x62\x8a\x31\xcd\x84\xb\xcf\x78\xe3\x62\xa\x64\x15\x2d\x27\x7a\x8c\x28\x2f\x42\x9e\x25\x2f\x7c\xf3\xdc\xc9\x89\x5a\x84\xf2\x6b\xfd\x4e\x6c\x91\x8d\x7f\xd9\x2b\xae\x67\x17\x89\xf4\x1\x9d\x0\x9d\x21\x21\xb7\x41\xb5\xcf\x12\xfc\xd8\xa5\xf\x43\x33\xa9\x8c\x75\x47\xbc\xa0\x7e\xf4\xe4\xc0\xe0\x7f\x95\x6b\x4b\xbb\x44\x3b\x98\x40\x7\x75\xb7\x1e\x35\x97\xf3\x4a\x5f\x7a\xa9\xc0\x5a\x74\x43\xe2\x44\x91\x69\x7b\xde\x75\x7f\x24\x45\xa\xb9\x3d\xa4\x2d\xcf\xe2\xc4\xa2\x48\xa2\xb9\x9c\xdf\x1b\x69\x93\xfd\x89\xfc\x79\x5d\xea\x9f\xf8\x56\xe2\xc1\x8e\x97\x80\x7b\x12\x5b\xa6\x57\xec\x20\xe3\x48\xf1\x34\x85\xc2\x3\x3e\x12\x25\x28\x88\x9d\xe3\x79\xcd\x0\x4d\x1c\xca\x61\xfd\xdb\x1e\x2a\xb6\xf\x13\xa8\x9e\x1c\xe7\x57\xa7\xb3\xdc\x9e\xd2\xcb\x7d\x26\x48\x78\xc3\x95\xe2\x1d\x19\x88\x26\xf8\x13\xa3\xe5\x5b\x76\x2b\x23\x5e\x42\x57\x2e\x1d\x84\x1d\x5d\x18\x14\xe7\x4d\x4f\xe3\xd3\xce\xd7\x58\x70\xc9\x68\xd7\x3d\xe\xb3\x28\xfc\x36\xa9\x3e\xdd\x2\x2a\xb8\xbd\x5a\xcf\x89\x94\xe3\x30\x66\x93\x99\x83\xf3\xb4\x8\x5b\x9c\xec\xc9\x1d\x9\x46\x12\xae\xa6\xb2\x74\xc4\xe3\x85\x22\xe8\x2\xb\xa3\x74\x73\xaf\x22\x56\x82\xd\xb6\x86\xb3\xb\xa8\xe1\x0\xf0\x69\xd\xa0\x55\x2\x3f\x94\xd6\x8c\xea\x4a\x9d\x88\x83\xa0\xbb\x31\xc0\xe5\x5e\x52\x6d\x9d\xb8\x6c\xea\x2\xba\xcc\x77\x78\x65\x84\x2f\x1b\x8d\x66\xa6\xe8\xe2\xdf\x3a\xa8\x55\x9a\xae\xba\xf5\xf6\xed\x40\x9b\xa0\xc4\x49\x16\x34\xcb\x77\xbe\x3a\x5e\xda\x2b\x8b\x71\xd2\x73\x4a\x3b\xeb\xf7\x36\x89\xac\x9b\x88\x63\x5b\xa1\x57\xad\xd4\x64\x1c\x26\x74\x77\x35\xa7\xe9\x4c\xa4\x11\xfa\xe5\xe4\xc3\xfb\xf9\xa9\xf9\xa1\x6c\xdf\xb5\x16\x7e\x6\x22\x34\x95\xc4\x38\x43\x81\x1b\x5a\x68\xd9\x7\xd5\x9e\x1\xf8\x1a\xbb\x7f\x15\x50\xfd\x96\x4a\x39\x39\x15\x9c\x71\xd6\xdc\xd0\x82\x20\x21\xe8\x13\x37\x54\xa7\xf2\xc0\xdb\xc6\xb5\x1d\x4e\x38\x40\x4d\xed\x14\x9d\x90\xdf\xe1\xfb\x29\xfa\x1a\x95\x67\xcc\xda\xaa\xa8\xed\x85\xbb\x7e\x9d\xa4\x92\x18\xae\xc\x99\x15\xd7\x7f\x9b\x3\x1\x6d\x6b\x43\x70\x40\x3c\xdd\x23\x68\x68\xcb\x91\x48\xd9\xc4\xca\x3c\xd9\xc7\x6d\x79\x33\x1\xb4\xa9\xac\x6b\x84\x63\x7e\xef\x27\x19\xd5\x72\xdc\x4a\xd1\xce\x52\xe9\xa9\x92\x39\x3f\x67\xe4\x62\xb8\x70\xcc\x4f\xcf\xe2\x83\x7c\x6b\x8\x3\x2e\xba\x36\x7c\x74\x2b\xed\x8\x67\xae\xfc\x85\xf\xf3\xa9\x97\x39\x1b\xb5\xce\x40\x99\xb8\x35\xd0\xe9\x5a\xb7\x51\x70\xff\xb8\xeb\x9c\x38\x7\x9a\x3f\x75\x5b\xcf\x20\x99\xe\x35\xa9\x62\x79\xd1\xff\xd9\x63\x44\x8b\xaa\x24\x81\x94\xd8\xbe\x1d\x59\xeb\x3f\xf5\x44\x5c\x1b\x14\xbe\xde\x3c\x4d\x7e\x82\xd4\x6\x4e\x20\x73\x1e\x2b\x83\xcc\x54\x76\xaa\x61\xf1\x2\x3c\xa0\x7f\x5a\xf3\x9e\x2f\x9\x4e\x5\x0\x75\x9\x6c\x42\x85\x98\xf2\x6b\xf3\xf1\xe6\x16\x71\x66\xf3\xc5\x38\xc0\x95\xab\xb0\xa5\xc0\x29\xe\xb9\xb7\xcd\xc3\x8\xa9\xe9\xf0\xc0\xf\x38\xc4\xf1\x92\xcf\xfc\x52\x5\x6c\x53\x36\x45\x97\x4c\xe3\xa\xed\xb1\x12\x78\xfa\x77\xcd\x13\x42\xdb\x36\x17\x44\x92\x7\x21\xa7\xb2\x35\xfe\x93\xe3\xc9\xff\x1a\x35\xce\x72\x71\x9e\x5b\x60\xf8\x7c\xc2\xa6\x15\xba\x63\x5a\xcd\x11\x35\x20\xa0\x2d\x10\x4a\x2\x94\x50\xd1\x7c\x2d\x77\xcb\x33\xef\x36\x10\x99\x3d\xf5\x50\xb3\xd7\x97\x75\x82\xd2\x50\xae\x4f\x7b\x60\x9a\x2e\x9a\xf\x1b\x87\xa4\x44\xb0\x2d\x31\xcb\x46\x21\x12\x12\xd\x86\x2d\x13\x33\x2e\xd2\x3f\x27\xfb\x77\x7d\x73\x9e\x10\xc2\xa4\x39\x65\x1f\xb2\x6c\xdf\x46\x14\x6f\x8b\xa2\x51\xa7\x70\xb9\x3a\x25\x2\x21\x47\xc5\xbe\x16\x55\x87\xf9\x81\xcd\x4d\x8a\xc6\xd3\x18\x49\x42\x7e\x3c\x2a\x58\x23\xd7\xf4\x1e\xd3\x14\x26\xcf\xe1\x93\x7\xbc\xfb\x9f\xc8\x88\x1c\xdc\xb6\x51\x42\xd7\x1f\xd6\x4c\x8b\xfc\x62\x88\x6e\x15\x7f\xd4\x3b\x3b\xb1\xd0\x6f\x51\xc9\x8a\x78\xe2\x25\x5d\xed\x86\xcf\x52\xf4\xdb\xe2\xcc\x61\x79\x19\xd6\x27\xa7\x30\xa\x5f\xb1\x24\x96\xb5\x2a\x10\xfb\x59\xae\xf8\x7f\xf5\x8d\xf6\xc3\x4e\x55\xf4\x90\x5\x61\xb7\xc5\xab\xd9\x12\x3d\xdf\x3c\x5c\xb\xa4\xed\x28\x27\x52\x0\x90\xe2\x1\x4d\xe8\xd6\xec\x37\xe6\x27\x9b\xf1\x6c\xab\xf\xb\xff\x82\xdd\xc7\x31\xa9\x8\x71\xfb\xe5\x15\xe1\x8e\xca\x58\xff\x9b\x44\xb3\x26\xa\x21\xab\xbc\x64\x6d\x14\x6\xf7\x3f\xb1\x8c\xe\x6\x50\xfb\x4a\xf5\x8f\x57\x65\x2f\x94\xf0\xe4\x72\xdc\x99\xbe\xff\x5f\xb6\x6e\xa0\xdd\x79\x3\x4f\x9f\x29\x5c\x0\x25\x20\x2\xa8\xc3\x5c\x58\x37\xf2\xf1\x8d\xfe\xee\x80\x84\xad\xb2\x9f\x58\xf7\x93\x8e\xc0\xf0\xb8\xf1\x17\xa1\xf2\x17\x14\x96\x8e\x92\xae\x89\x4e\x1e\xa4\xc2\xed\x49\x4e\x2c\xb4\xe\x61\xb3\x2b\x51\xfc\xc7\x78\x94\x76\x5b\x61\x85\x94\x80\xcf\x60\xeb\xa\xf4\x80\x76\x9c\x87\xb3\x9f\x77\x8d\x7c\xf4\xd9\xde\xa8\x87\x12\x50\xfa\x3b\x56\x9\x73\x26\x2\xfd\x22\x0\xe1\x96\xb9\x39\x7f\x9c\xb8\x88\x54\x85\x25\x35\xfb\xa7\x53\x4d\xd\x51\x66\x59\x86\xcd\xe3\xdb\x8f\x4c\x2e\x7a\x63\x3e\x78\x55\xf3\x6b\xc2\x86\x22\x2c\x99\x4b\xd3\xdc\x5\xe2\xa1\xc3\x61\xa3\x4d\x34\x5e\x2f\x9d\x69\x64\x51\xd9\xe3\x2\x90\x14\x6d\x3c\x7f\x13\x9f\x84\x8\xc6\x74\x99\xd7\xad\x9b\xb8\x2a\xd8\xff\x1e\x99\xe1\x45\xb4\xe6\x8e\x19\x2b\x33\x4\xa4\xec\xda\x35\x5d\xea\x40\x5c\x63\xd4\xfa\xb3\xd5\x3d\xda\xa8\xd7\x3b\x92\xcd\x7f\x80\x9c\x8\x1c\xd8\x96\xf1\x80\x3e\x34\x89\x5c\xf6\xbf\x39\xe7\x17\x42\xb0\x10\xbe\xd2\x1c\x33\xe8\x73\x48\x6\xd5\xd7\xff\x72\xea\x10\xc9\x9a\x15\xe3\xcb\x56\xbc\x69\xe7\xf5\xc1\xdf\x6c\xee\xd6\x35\xe5\xed\x3e\xf9\x15\x6e\xb\xc1\x73\xf\x9d\x1f\x85\x32\x1b\x64\xc3\x1e\x1c\xa7\xf2\x2\x76\x57\x98\x92\x18\xc4\xf0\x43\x49\xbe\x2\xda\x78\xcc\x12\x1e\xaa\x32\xf\x77\xa0\x7d\x4c\x14\x2f\x94\xb1\x60\x4b\x67\xab\x1b\x41\x92\x62\x47\xbb\xe6\x77\x8\xc7\x3e\xf9\x86\x8e\xf7\x7a\x2f\x93\xfc\xbe\xc2\x1\x7c\xe4\x62\xcf\x6d\x39\x36\x8b\x92\xf5\x24\x64\xb4\xfb\xd7\x59\x32\xf0\xac\xaf\xd4\x19\xd1\x92\xe1\x89\x6b\x85\xea\x7\xeb\xed\x2b\x68\xe3\xc\x56\xb4\x1f\xa8\xda\x36\xac\x4b\x78\xf\x56\x1f\xfe\xd8\x13\xfa\x2d\xda\xbe\xf6\xae\x66\x26\xba\x8b\xb\xbf\xc7\xca\x42\x64\x59\x4f\xc6\xcf\xd9\x8b\x64\x90\xc7\x1\xef\x32\xb9\xbf\x44\xe2\x82\xac\x1a\x18\xb4\xf8\x44\x94\x4\x28\x4e\x1c\x60\xe8\x87\x71\x4d\xda\xa\x89\xd6\xd1\x89\x7b\x73\xf1\x52\x7d\xd0\x56\x48\x13\xc2\x17\xba\x84\x30\x4c\x93\x51\xf6\x3f\x71\xfb\xe1\x1d\xd2\x37\xbc\x78\x97\x43\x57\x7c\xaf\x4a\xf3\xb0\xfd\xd8\x72\x3b\x5c\x72\x85\x1c\x5d\xb4\xcc\x4a\x8f\x4a\xca\x46\x42\xb8\x2b\x3d\x17\x16\xa\xe3\x6d\xf5\xd8\x53\x80\xf4\x7f\x87\x3e\x35\xc7\x61\xfa\x61\xd0\xf1\x96\x11\x4c\x4\xd9\x2\xa3\x87\x6f\x79\xea\x88\x3f\xd1\xee\xfe\xf1\xda\x35\x89\x4e\x11\x92\xbb\xd9\x63\xa1\x43\xb5\x5f\x72\x59\xff\xf7\x10\x29\xb4\xae\x2e\xba\xf1\x44\x2e\x6c\xfe\x80\x8c\xf5\x45\xe4\x42\xa0\xa9\xf9\x38\x4f\xf5\x56\x34\x45\x29\xf7\x96\xe0\x2\x65\xa3\x81\x28\x35\xbc\xa6\x93\x19\x19\x9b\x2f\x8f\x34\x87\x20\xc9\x77\x3b\x40\x8f\x74\xff\xd7\x3e\x28\x4b\xc6\x55\xf\x11\xb2\x7f\x90\xd8\x4e\xde\xf0\x2f\x6c\x19\x7e\xac\x76\xb7\xf2\x4b\x45\xf4\xb5\xe4\xac\x8b\x18\x1d\xb7\x3c\xde\xb\x76\xb5\x83\x4e\x25\x2e\x90\xcb\x51\x37\xb\x67\x1\x70\x49\x94\xe6\xaf\x94\x2a\x23\xa5\xad\x1e\x67\x51\xa5\xc7\xb3\x76\xee\xd1\xfb\xc3\xf5\xa3\x7c\x91\x5d\x7a\x57\x1b\xd4\x3c\xd4\xde\x5e\x1a\x65\x83\x89\xd0\xd2\x92\xc0\xbc\xd7\xc0\x29\x6e\x1\xbb\x4e\x32\xba\xf9\x9c\x14\xa0\x4b\x8b\xe\x44\xc8\xe7\x37\x88\xd\x2f\xb4\x1\x46\x11\x4f\xca\x8\xa0\xc9\xec\xfc\x90\x9d\x2e\x6a\xbf\xd0\x6b\x58\x30\x6c\x10\x30\xf2\xf\x22\x22\x72\xe6\xa9\xeb\xfa\x57\xf1\xa8\xa2\x5\xc7\xd6\xaa\xed\xb2\xb7\xcb\xd3\xde\x99\x96\xd4\xc1\xb0\x66\x10\x5\x82\x62\xf6\xd5\x89\x30\x94\xb3\x34\xe0\xcb\x3c\xf6\x4f\x6a\x12\x9f\x9e\x3f\x34\xf8\x52\x18\x5d\xae\x45\xaf\xde\x96\x58\xd\x6b\x41\xd3\xe4\xd5\xff\x4c\x46\x7b\x0\xfd\x92\x3e\xe3\x9a\xd4\xf1\x40\xe2\x57\x1e\x4c\x60\x9c\xec\x3\x9\xda\x6e\x3c\x90\x1b\xd0\x21\x96\xe5\xf5\xb9\xbf\xd9\x10\xc4\xfa\xf6\x6e\x75\xa6\x7\x35\xc8\x32\xb8\x14\x20\xd9\x79\x4e\x4c\x12\x2c\xbf\xed\xcc\x6\x70\xad\x1f\xb1\x91\x66\xf0\x52\x3\x8c\x37\xcd\xf0\xa8\xd3\xa1\x50\xa\xd\x4a\xda\x18\xc2\x10\xe0\xd2\xed\xc5\x45\x6e\xe6\xb8\x6a\x9\x65\x33\x52\x3d\x3d\xcc\x71\xf0\x36\x3\xfd\x19\xfa\x9b\xa7\x63\x4b\x17\x86\x75\xf0\x23\x30\xc\x8e\xdc\xb\x59\x5\x9d\x8f\xf9\xd6\x55\x1e\xeb\xf5\x6d\x2e\xb7\xcc\xa6\xe5\x68\x8a\x50\x58\xbf\xb1\x6\xe9\x38\x79\x43\x0\x62\x3a\x49\x23\xa9\x7\x9a\xe3\xa0\xbf\x95\x16\x82\x6f\xa6\x78\xf8\xc4\x1e\x60\x3c\x6b\x2d\x9f\x66\x76\xd2\x4\x3a\xa7\x54\x9d\x1f\x19\xf0\x93\xdd\xc2\xeb\xc4\x7d\xf7\x51\x59\x41\x8\x44\x48\x1c\x92\xa3\x96\x43\x2c\xc7\x30\x71\x55\xc7\x6c\x53\x99\x7d\xd8\xf5\x7e\x60\x30\xb9\xb9\x26\xba\x92\xff\x77\x97\xa3\x2c\xa0\xa0\xae\x42\x75\xc6\xce\xb3\xd0\xe6\xaf\x6\xe2\x16\xb\x46\x5a\x1e\x7d\x25\xb9\x39\x18\xa7\xff\xe2\xd8\xfa\xb9\xe0\xb7\x69\xd1\x38\x65\xff\x3b\xfa\x6b\x57\x19\xe3\x71\x6c\xd0\x9e\xc8\x33\xca\xd1\xb6\x2d\xc9\x3f\x1a\xde\x9a\x14\xd2\xfb\xd2\xd4\xaf\x96\xb\xd0\xe6\xa8\x72\xee\xdb\xab\x31\xd2\xfe\x40\x26\x9\x0\xea\x18\x5d\xa8\x3b\x5e\x8\x95\x2a\x3d\x2b\x12\x9f\x7f\xd9\xf5\x5b\xd7\x47\xeb\xa\xcf\xc0\x7b\x10\xa9\x46\xfc\xd\xb0\xe8\x4b\x32\x3e\x8c\x5c\xe1\x7d\xd1\x93\x94\x71\xc4\x1b\x85\xb5\xe4\xe2\xd3\xcd\xf5\x8f\xf3\xfe\xcc\x8c\x72\x12\x33\x56\x72\x4c\xb0\xea\xb6\xf7\xcd\x4d\x8b\x14\x15\xce\x30\xe6\x59\xad\x57\x41\xb8\xcf\x24\x26\x97\x8d\x8c\xf4\xfd\xe0\xfe\x5b\xcd\x97\x3a\xa4\x21\xfb\xef\xc1\x26\x1f\xb\xe6\xe3\xca\x5d\x6f\x86\x75\x72\x5a\xbe\x30\x20\xf2\xcb\x52\x6b\x7e\x5\x62\x89\x5\x10\x42\x2f\xd9\xda\x26\x35\x29\xe8\x1\xa8\x62\xa8\x83\x13\xfb\xbc\x5e\xa5\x6d\x10\xff\x94\x94\x6b\xf\x12\x92\x79\x0\xe7\x57\x44\xa\x8d\xa4\xb8\x72\x74\xc\x38\x82\xf0\x15\xf\x22\x7b\x9f\x18\x30\x5f\x59\x5a\xd8\x4a\xfe\xc\x67\x8b\x96\xf8\x61\xb0\xa\xe5\xe0\xba\xa2\x3a\x80\x3b\xfe\xe6\xb5\x84\xd5\x9f\x55\x6d\x54\x50\x78\x38\xae\x82\x9e\x44\xeb\xb3\x2d\xba\x49\x23\xe8\x2a\x5c\x2b\x33\x51\x47\x33\x61\xf0\xed\xf6\xb4\xe\x4e\xd3\xaa\x7\xa1\x6e\x91\x17\xcf\xea\x4a\x88\x8\x8a\x43\xa3\x55\x9b";
virtual_machine vm;

void start_stub_func(){
    __asm__("""start_stub: nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;""");
}

void print_logo(){
    char * c;
    setvbuf(stdout, NULL, _IONBF, 0);
    clearscreen();
    for(c = evildata; *c != '\x00'; c++){
        putchar(*c);
        usleep(500);
    }
    usleep(500000);
    printf("\t\t                                  :)");
    usleep(200000);
    clearscreen();
}

char * get_reg(char reg_num){
    switch ((unsigned char) reg_num)
    {
    case 0x83:
        return &vm.reg.reg1;
    case 0x81:
        return &vm.reg.reg2;
    case 0x85:
        return &vm.reg.reg3;
    case 0x82:
        return &vm.reg.reg4;
    case 0x84:
        return &vm.reg.reg5;
    }
    printf("Register not implemented: %x\n", reg_num);
    exit(1);
}

void get_regs(char **tmp1, char **tmp2){
    vm.reg.IP++;
    *tmp1 = get_reg(*vm.reg.IP);
    vm.reg.IP++;
    *tmp2 = get_reg(*vm.reg.IP);
}

char handler(){
    stack s;

    s.c.i = 0;

    while(1){
        //printf("IP: %p\n", vm.reg.IP);
        switch ((unsigned char) *vm.reg.IP)
        {
            case 0x99: // exit(reg1)
                return vm.reg.reg1;
            case 0x71: // cmp reg1 < reg2
                get_regs(&s.tmp1, &s.tmp2);
                if (*s.tmp1 < *s.tmp2)
                    vm.reg.flag = 1;
                else
                    vm.reg.flag = 0;
                break;
            case 0x76: // cmp reg1 == reg2
                get_regs(&s.tmp1, &s.tmp2);
                if (*s.tmp1 == *s.tmp2)
                    vm.reg.flag = 1;
                else
                    vm.reg.flag = 0;
                break;
            case 0x74: // flip flag
                vm.reg.flag = !vm.reg.flag;
                break;
            case 0x86: // jmp offset if flag set
                s.tmp1 = vm.reg.IP+1;
                s.tmp2 = vm.reg.IP+2;
                if (vm.reg.flag){
                    if(*s.tmp1==0x00)
                        vm.reg.IP = vm.reg.IP + *s.tmp2 -1;
                    else
                        vm.reg.IP = vm.reg.IP - *s.tmp2 -1;
                    vm.reg.flag = '\0';
                }else{
                    vm.reg.IP = vm.reg.IP+2;
                }
                break;
            case 0x91: // add reg1, reg2
                get_regs(&s.tmp1, &s.tmp2);
                *s.tmp1 = (*s.tmp1 + *s.tmp2) & 0xff;
                break;
            case 0x93: // sub reg1, reg2
                get_regs(&s.tmp1, &s.tmp2);
                *s.tmp1 = (*s.tmp1 - *s.tmp2) & 0xff;
                break;
            case 0x57: // addi reg1, byte
                s.tmp1 = get_reg(*(++vm.reg.IP));
                s.tmp2 = ++vm.reg.IP;
                *s.tmp1 = (*s.tmp1 + *s.tmp2) & 0xff;
                break;
            case 0x59: // subi reg1, byte
                s.tmp1 = get_reg(*(++vm.reg.IP));
                s.tmp2 = ++vm.reg.IP;
                *s.tmp1 = (*s.tmp1 - *s.tmp2) & 0xff;
                break;
            case 0x52: // div reg1, reg2
                get_regs(&s.tmp1, &s.tmp2);
                if (*s.tmp2 != 0){
                    *s.tmp1 = (*s.tmp1 / *s.tmp2) & 0xff;
                }else{
                    printf("Error: attempting division by 0.\n");
                    return -1;
                }
                break;
            case 0x90: // inc ro_data_ptr/data_ptr
                s.tmp1 = ++vm.reg.IP;
                if (*s.tmp1)
                    vm.reg.ro_data_ptr++;
                else
                    vm.reg.data_ptr++;
                break;
            case 0x89: // dec ro_data_ptr/data_ptr
                s.tmp1 = ++vm.reg.IP;
                if (*s.tmp1)
                    vm.reg.ro_data_ptr--;
                else
                    vm.reg.data_ptr--;
                break;
            case 0x98: // putchar ro_data_ptr/data_ptr
                s.tmp1 = ++vm.reg.IP;
                if (*s.tmp1)
                    putchar(*vm.reg.ro_data_ptr);
                else
                    putchar(*vm.reg.data_ptr);
                break;
            case 0x58: // puti
                s.tmp1 = ++vm.reg.IP;
                putchar(*s.tmp1);
                break;
            case 0x97: // getchar data_ptr
                *vm.reg.data_ptr = getchar();
                break;
            case 0x78: // load ro_data_ptr/data_ptr in reg
                s.tmp1 = ++vm.reg.IP;
                s.tmp2 = get_reg(*(++vm.reg.IP));
                if (*s.tmp1){
                    *s.tmp2 = *vm.reg.ro_data_ptr;
                }
                else{
                    *s.tmp2 = *vm.reg.data_ptr;
                }
                break;
            case 0x75: // store data_ptr from reg
                s.tmp1 = get_reg(*(++vm.reg.IP));
                *vm.reg.data_ptr = *s.tmp1;
                break;
            case 0x96: // mov reg1, reg2
                get_regs(&s.tmp1, &s.tmp2);
                *s.tmp1 = *s.tmp2;
                break;
            case 0x73: // jmp and push IP on cache, like a call
                s.tmp1 = ++vm.reg.IP;
                s.tmp2 = ++vm.reg.IP;
                vm.reg.IP++;
                s.c.cache[s.c.i] = vm.reg.IP;
                s.c.i++;
                if(*s.tmp1==0x00)
                    vm.reg.IP = vm.reg.IP + *s.tmp2;
                else
                    vm.reg.IP = vm.reg.IP - *s.tmp2;
                vm.reg.IP--;
                break;
            case 0x69: // ret using IP from cache
                s.c.i--;
                vm.reg.IP = s.c.cache[s.c.i];
                vm.reg.IP -= 1;
                break;
            default:
                return -1;
        }
        vm.reg.IP++;
    }
    return vm.reg.reg1;
}

int main(int argc,char *argv[]){
    FILE *fp;
    int code_len, ro_data_len, data_len;
    char res;
    if (argc < 2){
        printf("Usage: emulator file.ikiga1\n");
        return -1;
    }

    if((fp=fopen(argv[1], "rb"))==NULL) {
        printf("An error occourred while opening the program.\n");
        return -1;
    }

    fread(&code_len, sizeof(int), 1, fp);
    fread(&ro_data_len, sizeof(int), 1, fp);
    fread(&data_len, sizeof(int), 1, fp);

    vm.code_len = code_len;
    vm.ro_data_len = ro_data_len;
    vm.data_len = data_len;

    vm.code = malloc(code_len);
    vm.ro_data = malloc(ro_data_len);
    vm.data = malloc(data_len);

    fread(vm.code, code_len, 1, fp);
    fread(vm.ro_data, ro_data_len, 1, fp);
    vm.reg.IP = vm.code;
    vm.reg.ro_data_ptr = vm.ro_data;
    vm.reg.data_ptr = vm.data;

    print_logo();
    res = handler();

    return (int) res;
}