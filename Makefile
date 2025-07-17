obj-m += snapshot_mod.o
snapshot_mod-objs := \
	src/snapshot_auth.o \
	src/snapshot_mod.o

EXTRA_CFLAGS := -I$(PWD)/include

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
