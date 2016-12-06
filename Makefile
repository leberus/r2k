ARCH_ARM := $(shell uname -m | grep -c "[arm|aarch]")

ifeq ($(ARCH_ARM),1)
	FOLDER := arm
else
	FOLDER := x86
endif

FOLDER := arm

CFLAGS_r2kmod.o := -DDEBUG
obj-m += r2kmod.o
r2kmod-objs := r2k.o arch/$(FOLDER)/arch_functions.o arch/$(FOLDER)/dump_pagetables.o

all:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=~/lab/build-android/AOSP/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-androidkernel- -C ~/repository/goldfish/ M=$(PWD) modules

clean:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=~/lab/build-android/AOSP/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-androidkernel- -C ~/repository/goldfish/ M=$(PWD) clean

