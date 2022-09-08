MODNAME = kreap

SRCS = ./src/kernel/kreap.c

OBJS = $(SRCS:.c=.o)

obj-m += $(MODNAME).o
$(MODNAME)-y = $(OBJS)

KVERSION = $(shell uname -r)

publish: module chall
	strip $(PWD)/build/$(MODNAME).ko --strip-unneeded
	strip $(PWD)/build/chall
	cp $(PWD)/build/$(MODNAME).ko $(PWD)/build/chall $(PWD)/attachments/ 

module: build_module clean_module

build_module:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	mv -v $(PWD)/$(MODNAME).ko $(PWD)/build/$(MODNAME).ko

clean_module:
# make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -v $(PWD)/Module.symvers
	rm -v $(PWD)/modules.order $(PWD)/.*.cmd $(PWD)/*.o $(PWD)/kreap.mod $(PWD)/kreap.mod.c
	rm -v $(PWD)/src/kernel/*.o $(PWD)/src/kernel/.*.cmd

chall:
	gcc -o $(PWD)/build/chall -s src/main.c