ifeq ($(shell which x86_64-elf-gcc 2>/dev/null),)
    CC := gcc
    AS := as
    LD := ld
    OBJCOPY := objcopy
else
    CC := x86_64-elf-gcc
    AS := x86_64-elf-as
    LD := x86_64-elf-ld
    OBJCOPY := x86_64-elf-objcopy
endif

BUILD_DIR := build
KERNEL_DIR := kernel
USER_DIR := user

CFLAGS := -ffreestanding -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
          -fno-stack-protector -fno-pic -mcmodel=kernel \
          -Wall -Wextra -Werror -O2
ASFLAGS :=
LDFLAGS := -nostdlib -static

KERNEL_CFLAGS := $(CFLAGS) -I$(KERNEL_DIR)
KERNEL_LDFLAGS := $(LDFLAGS) -T $(KERNEL_DIR)/linker.ld

USER_CFLAGS := -ffreestanding -mno-red-zone -mno-mmx -mno-sse -mno-sse2 \
               -fno-stack-protector -fno-pic \
               -Wall -Wextra -O2
USER_LDFLAGS := $(LDFLAGS) -e _start

KERNEL_C_SRCS := $(wildcard $(KERNEL_DIR)/*.c)
KERNEL_S_SRCS := $(wildcard $(KERNEL_DIR)/*.S)
KERNEL_OBJS := $(patsubst $(KERNEL_DIR)/%.c,$(BUILD_DIR)/kernel/%.o,$(KERNEL_C_SRCS)) \
               $(patsubst $(KERNEL_DIR)/%.S,$(BUILD_DIR)/kernel/%.o,$(KERNEL_S_SRCS))

USER_PROGS := init uname id sh ls cat echo pwd
USER_COMMON := $(BUILD_DIR)/user/start.o $(BUILD_DIR)/user/libc.o

EMBEDDED_BINS := $(addprefix $(BUILD_DIR)/user/,$(addsuffix .elf,$(USER_PROGS)))
EMBEDDED_OBJS := $(addprefix $(BUILD_DIR)/embed/,$(addsuffix .o,$(USER_PROGS)))

.PHONY: all clean run

all: $(BUILD_DIR)/iruel.bin

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/kernel $(BUILD_DIR)/user $(BUILD_DIR)/embed

$(BUILD_DIR)/kernel/%.o: $(KERNEL_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(KERNEL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/kernel/%.o: $(KERNEL_DIR)/%.S | $(BUILD_DIR)
	$(CC) $(KERNEL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/user/%.o: $(USER_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/user/%.o: $(USER_DIR)/%.S | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/user/init.elf: $(BUILD_DIR)/user/init.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/uname.elf: $(BUILD_DIR)/user/uname.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/id.elf: $(BUILD_DIR)/user/id.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/sh.elf: $(BUILD_DIR)/user/sh.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/ls.elf: $(BUILD_DIR)/user/ls.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/cat.elf: $(BUILD_DIR)/user/cat.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/echo.elf: $(BUILD_DIR)/user/echo.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/user/pwd.elf: $(BUILD_DIR)/user/pwd.o $(USER_COMMON)
	$(LD) $(USER_LDFLAGS) -T $(USER_DIR)/linker.ld $^ -o $@

$(BUILD_DIR)/embed/init.o: $(BUILD_DIR)/user/init.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/init.o init.elf

$(BUILD_DIR)/embed/uname.o: $(BUILD_DIR)/user/uname.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/uname.o uname.elf

$(BUILD_DIR)/embed/id.o: $(BUILD_DIR)/user/id.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/id.o id.elf

$(BUILD_DIR)/embed/sh.o: $(BUILD_DIR)/user/sh.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/sh.o sh.elf

$(BUILD_DIR)/embed/ls.o: $(BUILD_DIR)/user/ls.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/ls.o ls.elf

$(BUILD_DIR)/embed/cat.o: $(BUILD_DIR)/user/cat.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/cat.o cat.elf

$(BUILD_DIR)/embed/echo.o: $(BUILD_DIR)/user/echo.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/echo.o echo.elf

$(BUILD_DIR)/embed/pwd.o: $(BUILD_DIR)/user/pwd.elf | $(BUILD_DIR)
	cd $(BUILD_DIR)/user && $(LD) -r -b binary -o ../embed/pwd.o pwd.elf

$(BUILD_DIR)/kernel/initramfs.o: $(EMBEDDED_BINS) | $(BUILD_DIR)
	@echo "Generating initramfs..."
	@echo '' > $(BUILD_DIR)/initramfs.c
	@echo '#include <stdint.h>' >> $(BUILD_DIR)/initramfs.c
	@echo '#include <stddef.h>' >> $(BUILD_DIR)/initramfs.c
	@echo '' >> $(BUILD_DIR)/initramfs.c
	@for prog in $(USER_PROGS); do \
		echo "extern char _binary_$${prog}_elf_start[];" >> $(BUILD_DIR)/initramfs.c; \
		echo "extern char _binary_$${prog}_elf_end[];" >> $(BUILD_DIR)/initramfs.c; \
		echo "extern char _binary_$${prog}_elf_size[];" >> $(BUILD_DIR)/initramfs.c; \
		echo "" >> $(BUILD_DIR)/initramfs.c; \
	done
	@echo '' >> $(BUILD_DIR)/initramfs.c
	@echo 'typedef struct {' >> $(BUILD_DIR)/initramfs.c
	@echo '    const char *name;' >> $(BUILD_DIR)/initramfs.c
	@echo '    void *data;' >> $(BUILD_DIR)/initramfs.c
	@echo '    size_t size;' >> $(BUILD_DIR)/initramfs.c
	@echo '} initramfs_file_t;' >> $(BUILD_DIR)/initramfs.c
	@echo '' >> $(BUILD_DIR)/initramfs.c
	@echo 'initramfs_file_t initramfs_files[] = {' >> $(BUILD_DIR)/initramfs.c
	@for prog in $(USER_PROGS); do \
		echo "    { \"/bin/$$prog\", _binary_$${prog}_elf_start, (size_t)_binary_$${prog}_elf_size }," >> $(BUILD_DIR)/initramfs.c; \
	done
	@echo '    { NULL, NULL, 0 }' >> $(BUILD_DIR)/initramfs.c
	@echo '};' >> $(BUILD_DIR)/initramfs.c
	@echo '' >> $(BUILD_DIR)/initramfs.c
	@echo 'int initramfs_count = sizeof(initramfs_files) / sizeof(initramfs_files[0]) - 1;' >> $(BUILD_DIR)/initramfs.c
	$(CC) $(KERNEL_CFLAGS) -c $(BUILD_DIR)/initramfs.c -o $@

$(BUILD_DIR)/iruel.elf: $(KERNEL_OBJS) $(BUILD_DIR)/kernel/initramfs.o $(EMBEDDED_OBJS)
	$(LD) $(KERNEL_LDFLAGS) $^ -o $@

$(BUILD_DIR)/iruel.bin: $(BUILD_DIR)/iruel.elf
	$(OBJCOPY) -O elf64-x86-64 $< $@

run: $(BUILD_DIR)/iruel.bin
	./scripts/run-qemu.sh

run-gui: $(BUILD_DIR)/iruel.bin
	qemu-system-x86_64 -kernel $< -m 128M

clean:
	rm -rf $(BUILD_DIR)
