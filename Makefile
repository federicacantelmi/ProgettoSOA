obj-m += snapshot_mod.o
snapshot_mod-objs := \
	src/snapshot_auth.o \
	src/snapshot_mod.o \
	src/snapshot_api_dev.o \
	src/snapshot_api.o \
	src/snapshot.o \
	src/snapshot_kprobe_mount.o

EXTRA_CFLAGS := -I$(PWD)/include

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
