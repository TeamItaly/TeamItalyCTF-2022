#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <sys/prctl.h>

//Orders Structure

#define MAX_ORDERS 20
#define MAX_TITLE_LENGTH 20
#define MAX_ORDER_LENGTH 200

struct order {
    char by[MAX_TITLE_LENGTH];
    char description[MAX_ORDER_LENGTH];
} *orders[MAX_ORDERS+1];

int last_order;

#define SAFETY_ON (orders[0] != NULL && orders[0]->description[0] == '1')
#define VALID_ORDER_IND(__ind) (__ind >= 0 && __ind <= MAX_ORDERS)

//New STDFUNCTION

int safe_strcmp(const char* str1, const char* str2){
    for (size_t i=0;;i++){
        if (str1[i] == 0 || str2[i] == 0)
            return (int)(str1[i])-(int)(str2[i]);
        int tmp = (int)(str1[i])-(int)(str2[i]);
        if (tmp != 0) return tmp;
    }
}

int _strcmp(const char* str1, const char* str2){
    if (SAFETY_ON){
        return safe_strcmp(str1, str2);
    }else{
        return strcmp(str1, str2);
    }
}

void* safe_memset(void *str, int c, size_t n){
    for (void* p = str; p<str+n; p++){
        *(char*)p = c;
    }
    return str;
}

void* _memset(void *str, int c, size_t n){
    if (SAFETY_ON){
        return safe_memset(str, c, n);
    }else{
        return memset(str, c, n);
    }
}

size_t safe_strlen(const char * str){
    size_t res = 0;
    for (const char* p=str; *p!=0; p++) res++;
    return res;
}

size_t _strlen(const char * str){
    if (SAFETY_ON){
        return safe_strlen(str);
    }else{
        return strlen(str);
    }
}

struct malloc_node {
    size_t size;
    struct malloc_node *next;
};

struct malloc_node * head_malloc_pointer = NULL, * tail_malloc_pointer = NULL;
#define MALLOC_HEADER sizeof(struct malloc_node)
#define MALLOC_NODE_MEM(__ptr) ((void*)(((void *)__ptr)+MALLOC_HEADER))
#define MALLOC_NODE_BY_MEM(__ptr) ((struct malloc_node *)(((void *)__ptr)-MALLOC_HEADER))

void* safe_malloc(size_t size){
    struct malloc_node* res = (struct malloc_node *)mmap( NULL, size+sizeof(struct malloc_node), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0 );
    if(res == MAP_FAILED){
        fputs("Mapping Failed\n", stderr);
        exit(1);
    }
    res->size = size;
    if (head_malloc_pointer == NULL){
        head_malloc_pointer = res;
        tail_malloc_pointer = res;
        res->next = NULL;
    }else{
        tail_malloc_pointer->next = res;
        res->next = NULL;
        tail_malloc_pointer = res;
    }
    return MALLOC_NODE_MEM(res);
}

void* _malloc(size_t size){
    if (SAFETY_ON){
        return safe_malloc(size);
    }else{
        return malloc(size);
    }
}

void unlink_malloc_node(struct malloc_node *prev, struct malloc_node *node){
    if (prev == NULL){
        head_malloc_pointer = node->next;
        if (node->next == NULL) tail_malloc_pointer = NULL;
    }else{
        prev->next = node->next;
    }
    if (node->next == NULL) tail_malloc_pointer = prev;
}

bool safe_free(void * ptr){
    if(ptr == NULL) return false;
    struct malloc_node* node = MALLOC_NODE_BY_MEM(ptr);
    struct malloc_node* prev_pointer = NULL;
    for(struct malloc_node* p = head_malloc_pointer; p!=NULL; p = p->next){
        if (p == node){
            unlink_malloc_node(prev_pointer, p);
            if (munmap(node, node->size+sizeof(struct malloc_node)) != 0){
                fputs("Mapping Failed\n", stderr);
                exit(1);
            }
            return true;
        }
        prev_pointer = p;
    }
    return false;
}

void _free(void* ptr){
    if (!safe_free(ptr)) free(ptr);
}

void* safe_memcpy ( void * destination, const void * source, size_t num ){
    for (size_t i=0; i<num; i++){
        ((char*)destination)[i] = ((char*)source)[i];
    }
    return destination;
}

void* _memcpy( void * destination, const void * source, size_t num ){
    if (SAFETY_ON){
        return safe_memcpy(destination, source, num);
    }else{
        return memcpy(destination, source, num);
    }
}

void* safe_strncpy ( char * destination, const char * source, size_t num ){
    size_t i;
    for (i=0; i<num && i<_strlen(source); i++){
        destination[i] = source[i];
    }
    if (i<num) destination[i] = 0;
    else destination[num-1] = 0;
    return destination;
}

void* _strncpy( void * destination, const void * source, size_t num ){
    if (SAFETY_ON){
        return safe_strncpy(destination, source, num);
    }else{
        return strncpy(destination, source, num);
    }
}

void _readline(char* buf, size_t size){
    char * res;
    if (SAFETY_ON){
        res = fgets(buf, size-1, stdin);
        buf[_strlen(buf)-1] = 0;
    }else{
        res = gets(buf);
    }
    if (res == NULL){
        fputs("Reading Failed\n", stderr);
        exit(1);
    }
}

void _println(char* str){
    if (SAFETY_ON){
        puts(str);
    }else{
        size_t len = _strlen(str);
        char buf[len+2];
        _memcpy(buf, str, len);
        buf[len] = '\n';
        buf[len+1] = 0;
        printf(buf);
    }
}

//Signature Managment

uint16_t secret = 0x0000;

void __cyg_profile_func_enter (void *this_fn, void *call_site) __attribute__((no_instrument_function));
void __cyg_profile_func_exit  (void *this_fn, void *call_site) __attribute__((no_instrument_function));
void signature_secret_gen() __attribute__((constructor, no_instrument_function));

void __cyg_profile_func_enter (void *this_fn, void *call_site){
    __asm__ (
        "pop %%rbp;                             \n" //Reset stack pointers
        "pop %%rdx;                             \n" //Get return value

        "mov %[secret], %%ax;                   \n" //Assign value of the secret
        
        "mov $14, %%rcx;                        \n" //Set the number of bytes to write (excluding the first 2 of the ret pointer)
                                                    //Where will be written the signature, and that are 0x00
        "sig_calc__cyg_profile_func_enter:      \n" //INIT of loop
        "test %%rcx, %%rcx;                     \n" //Check if is the end of loop
        "je end_sig__cyg_profile_func_enter;    \n" //If is the end of loop, jump to the end of the loop
        "dec %%rcx;                             \n" //Decrement the number of bytes to write
        "xor (%%rbp), %%al;                     \n" //Calculating signature with the first byte of the secret
        "xor (%%rbp), %%ah;                     \n" //Calculating signature with the second byte of the secret
        "inc %%rbp;                             \n" //Increment pointer to next byte to sign
        "jmp sig_calc__cyg_profile_func_enter;  \n" //Loop
        "end_sig__cyg_profile_func_enter:       \n" //End of the loop
        "mov %%ax, (%%rbp);                     \n" //Assign signature to fist 2-bytes of return address (that is likely to be 0x0000)
        "sub $14, %%rbp;                        \n" //Reset base pointer

        "jmp *%%rdx;                            \n" //return to back function
        : 
        : [secret] "r" (secret)
        : "memory"
    );
}

void __stack_signature_failed(void)
{
    fputs("OOPS! Our advanced security checks detected a stack smash!\n---------------- Stack signature failed ----------------\n", stderr);
    exit(1);
}

void __cyg_profile_func_exit  (void *this_fn, void *call_site){
    __asm__ (
        "pop %%rbp;                             \n" //Reset stack pointers
        "pop %%rdx;                             \n" //Get return value

        "mov %[secret], %%ax;                   \n" //Assign value of the secret
        
        "mov $14, %%rcx;                        \n" //Set the number of bytes to write (excluding the first 2 of the ret pointer)
                                                    //Where will be written the signature, and that are 0x00
        "sig_calc__cyg_profile_func_exit:       \n" //INIT of loop
        "test %%rcx, %%rcx;                     \n" //Check if is the end of loop
        "je end_sig__cyg_profile_func_exit;     \n" //If is the end of loop, jump to the end of the loop
        "dec %%rcx;                             \n" //Decrement the number of bytes to write
        "xor (%%rbp), %%al;                     \n" //Calculating signature with the first byte of the secret
        "xor (%%rbp), %%ah;                     \n" //Calculating signature with the second byte of the secret
        "inc %%rbp;                             \n" //Increment pointer to next byte to sign
        "jmp sig_calc__cyg_profile_func_exit;   \n" //Loop
        "end_sig__cyg_profile_func_exit:        \n" //End of the loop
        "xor %%ax, (%%rbp);                     \n" //xor the value with the old_signature, this will reset the return pointer
        "mov (%%rbp), %%ax;                     \n" //Copy the signature space for the check to 0x0000 (avoid segfault)
        "sub $14, %%rbp;                        \n" //Reset base pointer

        "test %%ax, %%ax;                       \n" //Check if signature is correct
        "je end__cyg_profile_func_exit;         \n" //If not, jump to the return address
        "call __stack_signature_failed;         \n" //Call exit
        "end__cyg_profile_func_exit:            \n" //End of function

        "jmp *%%rdx;                            \n" //return
        : 
        : [secret] "r" (secret)
        : "memory"
    );
}

void signature_secret_gen() {
    FILE *fp = fopen("/dev/urandom", "r");
    fread(&secret, sizeof(secret), 1, fp);
    fclose(fp);
}

//END Signature managment

int readint(){
    char buf[10];
    _readline(buf, 10);
    return atoi(buf);
}

size_t fsize(FILE *fp){
    size_t pos = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    size_t res = ftell(fp);
    fseek(fp, pos, SEEK_SET);
    return res;
}

bool set_order(unsigned int ind, char* title, char* content){
    if (!VALID_ORDER_IND(ind)) return false;
    if (orders[ind] == NULL){
        orders[ind] = (struct order *)_malloc(sizeof(struct order));
    }
    _strncpy(orders[ind]->by, title, MAX_TITLE_LENGTH);
    _strncpy(orders[ind]->description, content, MAX_ORDER_LENGTH);
    return true;
}

bool unset_order(unsigned int ind){
    if (!VALID_ORDER_IND(ind)) return false;
    if (orders[ind] == NULL) return false;
    _free(orders[ind]);
    orders[ind] = NULL;
    return true;
}

void orders_fast_list(){
    _println("*******************************");
    for(size_t i=1;i<=MAX_ORDERS;i++){
        if(orders[i] != NULL){
            printf("ID: %d, Title: %s\n", i, orders[i]->by);
        }
    }
    _println("*******************************");
}

void banner(){
    FILE* banner = fopen("banner.txt","r");
    if (banner == NULL){
        puts("No banner for you :(");
    }else{
        size_t size = fsize(banner)+1;
        char* content = (char *)malloc(size);
        if (content == NULL){
            fputs("We check also if malloc returns 0, Nothing to do :)\n", stderr);
            exit(1);
        }else{
            content[size-1] = 0;
            size_t tmp = fread(content,sizeof(char), size,  banner);
            puts(content);
            free(content);
        }
    }
    
}

int interactive_order_choose(){
    while (true){
        printf("Choose order (from %d to %d) > ", 1, MAX_ORDERS);
        int res = readint();
        if (res < 0) return res;
        last_order = res;
        if (res >= 1 && res <= MAX_ORDERS){
            return res;
        }else{
            _println("Invalid order number, try again");
        }
    }
}

void interactive_unset_order(unsigned int ind){
    if(!VALID_ORDER_IND(ind)) return;
    if(unset_order(ind)){
        _println("Done!");
    }else{
        _println("Operation Failed!");
    }
}

void interactive_set_order(unsigned int ind){
    if(!VALID_ORDER_IND(ind)) { _println("Invalid Order!"); return;}
    char title[MAX_TITLE_LENGTH];
    char content[MAX_ORDER_LENGTH];
    printf("Ordered By > ");
    _readline(title, MAX_TITLE_LENGTH);
    printf("Description > ");
    _readline(content, MAX_ORDER_LENGTH);
    if(set_order(ind, title, content)){
        _println("Done!");
    }else{
        _println("Operation Failed!");
    }
}

int get_free_orderid(){
    for(size_t i=1;i<=MAX_ORDERS;i++){
        if (orders[i] == NULL){
            last_order = i;
            return i;
        }
    }
    return -1;
}

void order_print(unsigned int ind){
    if(!VALID_ORDER_IND(ind)) { _println("Invalid Order!"); return;}
    if(orders[ind] == NULL){
        _println("Invalid Order!");
        return;
    }
    _println("***********************************");
    printf("--> OrderID: %d, Ordered-By: %s", ind, orders[ind]->by);
    if (!SAFETY_ON){
        printf("\n---> Advanced details: %p",orders[ind]);
    }
    _println("\n***********************************");
    _println(orders[ind]->description);
    _println("***********************************");
}


void initialize(){
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_load(ctx);
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    set_order(0,"SAFETY MODE", "1");
    last_order = -1;
}

int menu(){
    _println("----------------------------");
    _println("Choose an option:\n");
    _println("1) Add an order");
    _println("2) Edit order");
    _println("3) Remove order");
    _println("4) View order");
    _println("5) View last opened order");
    _println("6) Re-Add/Edit last opened order");
    _println("7) Delete last opened order");
    _println("8) View all orders");
    _println("9) Delete all orders");
    _println("-1) Exit");
    printf("\n> ");
    int res = readint();
    _println("----------------------------");
    return res;
}

int main(){

    initialize();
    banner();
    
    while (true){
        switch(menu()){
            case -1:
                _println("Shutting down...");                       
                return 0;
            case 1:
                interactive_set_order(get_free_orderid());
                break;
            case 2:
                orders_fast_list();
                interactive_set_order(interactive_order_choose());
                break;
            case 3:
                orders_fast_list();
                interactive_unset_order(interactive_order_choose());
                break;
            case 4:
                order_print(interactive_order_choose());
                break;
            case 5:{
                if (last_order<0) _println("No order opened");
                else order_print(last_order);
                break;
            }
            case 6:{
                if (last_order<0) _println("No order opened");
                else interactive_set_order(last_order);
                break;
            }
            case 7:{
                if (last_order<0) _println("No order opened");
                else interactive_unset_order(last_order);
                break;
            }
            case 8:{
                for(size_t i=1;i<=MAX_ORDERS;i++)
                    if (orders[i] != NULL) order_print(i);
                break;
            }
            case 9:{
                for(size_t i=1;i<=MAX_ORDERS;i++) unset_order(i);
                _println("All orders deleted!");
                break;
            }
            default:{
                _println("Invalid option");
                break;
            }
        }
    }
}

//gcc chall.c -o chall -std=gnu99 -finstrument-functions -lseccomp
