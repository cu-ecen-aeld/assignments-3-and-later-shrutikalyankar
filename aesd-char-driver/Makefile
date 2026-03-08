ifneq ($(KERNELRELEASE),)
# Kernel build context
obj-m := aesdchar.o
aesdchar-objs := main.o aesd-circular-buffer.o

else
# Host / cross-compile context
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

endif
