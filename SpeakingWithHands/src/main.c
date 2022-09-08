#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include "bin.h"
#define FLAG_LEN 15

typedef int func(void *ptr, void *fun, int offset, int size);

void print_flag(char * realFlag) {
  asm("sub $8, %rsp"); // align stack
  printf("flag{%s}\n", realFlag);
}

char license[30];
void *lib_functions_and_flag[] = {malloc, free, print_flag, ";?QKKGg!E:Cn[[\\", license};
void *code_area;

char instr[] = {
    'x', 'y', '!', 'a', '1', 'r', 'O', 'l', '2', 'W', 'S', 'b', '?', 'j', 'h'};
int mapping[] = {0x5e, 0x6e, 0x7e, 0x8e, 0x9e, 0xae, 0xba, 0xc6, 0xd5, 0xe4, 0xf3, 0x10f, 0x139, 0x14d, 0x15f, 0x171, 0x17d};

int get_offset(char i)
{
  int c = 0;

  while (c < 16 && i != instr[c])
    c++;
  return c;
}

int main()
{
  char *license_ptr = license;
  int offset;
  code_area = valloc(1000);
  mprotect(code_area, 1000, PROT_READ | PROT_WRITE | PROT_EXEC);
  memcpy(code_area, BIN_CODE, 1000);

  puts("                                            .::~^^^^^~7~^^^:::::..                                  \n                                           .^..~^^^^:::.  ....:^~~^^:.                              \n                                           7^. ^:^^^^~~:.          .:^^^:.                          \n                                        .::~:.    .::^:.:^!^:.         .:^~^.                       \n                                      .!~~~~~~!^.        .^^^^^!!:         .^~^.                    \n                                      ~!.     :!::.            .^~^.          .:^:.                 \n                                      ~!       ~^ :^:             .^^^:          .:^^.              \n                                      .J:       7.  :~^              .^~^:          .:^!~.          \n                                       !? :::^^^7.    ^!.    .^:        .^~^:          ^!7          \n                                       .Y!^^^^^:.      7~^:~77^            .^~^^!:       ~^         \n                                        !^             :!:^.!:                .~?!.       7         \n                                        .7              7.:~:^^:.               ~77^      ~:        \n                                         !^   ....      :!  :^^^~~.                ~~     .!        \n                                         .7.^^^:::..     7.   .??~~^:.              ^~     !.       \n                                          ~~:^^^^^^:     ~^    ~^.  :~^:^:::         ^!    ^^       \n                                          .7 .:^^:.      .7    ~^     ~J7^.           :!   .!       \n                                           ~^             7.   .7      7.              :!   ~.      \n                                            7             ^~    ^~.:   ^7.              .!. :^      \n                                            ~:             !:   .7~: .:..~:              .!. ^      \n                                            ^~              ~^ :^.        !~.             .!:^      \n                                            :~               ^!.         ^~!^^:..           ~~.     \n                                            :~                :~       .^:7^  .....          ~^     \n                                            ^^                 :!::::..:.^^.                  ^:    \n                                            ~.  ..         ..   .^:..::^^~^^:                  .:   \n                                            ^  .^           .^    .::.  ....^~^:.....            :. \n                                           ..  ~.            ~.    .7~: .:~~: ..^~^:.             ^.\n                                          ..   ~             ~.     .!!~^...::.    ....            ^\n                                         ::    ~.            ~        !..::.                       .\n                                        :^     .:           .:        .:                           .\n                                       .~       ..                                               .:.\n                                       ~.                                                      .:.  \n                                      ^^                                                     .::    \n                                     .!                                                    .^:.     \n                                     !.                                                  .^:        \n                                    :!                                                 .^^          \n                                    ^~                                               .^^            \n                                    ^~                                             .^^.             \n                                    !:                                           .^~.               \n                                   !^                                           ^~:                 \n                                  ^~                                          ^~:                   \n                                  !^                                        :^:                     \n                               .:~^                                       :^:                       \n                           .:^~^:                                       :~^                         \n                       .:^^^:.                                        :~^.                          \n                  .::^^^:.                                          .~^.                            ");
  puts("Welcome to 🤌 -> English traslator \nWARNING: this is a paid software, you need a VALID license key \nInsert license: ");

  fgets(license, 30, stdin);

  if (strlen(license) != FLAG_LEN+1)
  {
    return 1;
  }

  if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1)
    return 1;

  while (license_ptr < license + FLAG_LEN)
  {
    offset = get_offset(*license_ptr);

    license_ptr += ((func *)code_area)(license_ptr, lib_functions_and_flag, mapping[offset], mapping[offset+1] - mapping[offset]);
  }

  return 0;
}
