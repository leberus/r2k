ARCH=$(shell uname -m)

ifeq ($(ARCH), x86_64)
	FOLDER := x86
else ifeq ($(ARCH), arm)
	FOLDER := arm
else ifeq ($(ARCH), i686)
	FOLDER := x86
else ifeq ($(ARCH), arm)
	FOLDER := arm
else
        $(error Bad architecture)
endif

obj-m += r2kmod.o
r2kmod-objs := r2k.o arch/$(FOLDER)/arch_functions.o
#CFLAGS_r2kmod.o := -DDEBUG


all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
