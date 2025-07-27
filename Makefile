obj-m += snapshot_mod.o
snapshot_mod-objs := \
	src/snapshot_auth.o \
	src/snapshot_mod.o \
	src/snapshot_api_dev.o \
	src/snapshot_api.o \
	src/snapshot.o \
	src/snapshot_kprobe.o

EXTRA_CFLAGS := -I$(PWD)/include

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Parametro PASSW per il modulo
PASSW ?=

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	@if [ -z "$(PASSW)" ]; then \
		echo "Please provide a password using PASSW=your_password"; \
		exit 1; \
	fi
	@echo "Installing snapshot_mod with password: $(PASSW)"
	sudo mkdir -p /snapshot
	sudo chown root:root /snapshot
	sudo chmod 755 /snapshot
	-sudo rmmod snapshot_mod || true
	sudo insmod snapshot_mod.ko snapshot_password=$(PASSW) || sudo modprobe snapshot_mod snapshot_password=$(PASSW)
	@echo "Snapshot module installed successfully."

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

uninstall:
	-sudo rmmod snapshot_mod
	@if [ -d /snapshot ]; then \
		sudo rm -rf /snapshot; \
	else \
		echo "/snapshot directory does not exist."; \
	fi
	@echo "Snapshot module uninstalled and /snapshot directory removed."
