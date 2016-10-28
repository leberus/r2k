TARGET_CPU := arm

ifeq ($(filter arm,$(shell arch)),)
	FOLDER := arm
else ifeq ($(filter x86,$(shell arch)),)
	FOLDER := x86
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
