#include "include/kernel.h"
#include "include/memory.h"
#include "include/process.h"
#include "include/syscall.h"
#include "include/fs.h"
#include "include/procfs.h"

typedef struct {
    const char *name;
    void *data;
    size_t size;
} initramfs_file_t;

extern initramfs_file_t initramfs_files[];
extern int initramfs_count;

#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36d76289

#define MULTIBOOT_TAG_TYPE_END              0
#define MULTIBOOT_TAG_TYPE_BASIC_MEMINFO    4
#define MULTIBOOT_TAG_TYPE_MMAP             6

struct multiboot_tag {
    uint32_t type;
    uint32_t size;
};

struct multiboot_tag_basic_meminfo {
    uint32_t type;
    uint32_t size;
    uint32_t mem_lower;
    uint32_t mem_upper;
};

static void early_serial_init(void) {
    outb(0x3F8 + 1, 0x00);
    outb(0x3F8 + 3, 0x80);
    outb(0x3F8 + 0, 0x03);
    outb(0x3F8 + 1, 0x00);
    outb(0x3F8 + 3, 0x03);
    outb(0x3F8 + 2, 0x01);
    outb(0x3F8 + 4, 0x0B);
}

static void early_serial_write(const char *s) {
    while (*s) {
        while ((inb(0x3F8 + 5) & 0x20) == 0);
        outb(0x3F8, *s++);
    }
}

static uint64_t parse_multiboot(uint32_t magic, uint32_t addr) {

    if (magic != MULTIBOOT2_BOOTLOADER_MAGIC) {

        early_serial_write("warning: no multiboot2 magic, assuming 128mb ram\r\n");
        return 128 * 1024;
    }

    uint64_t mem_upper = 0;
    struct multiboot_tag *tag = (struct multiboot_tag *)(uint64_t)(addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_BASIC_MEMINFO) {
            struct multiboot_tag_basic_meminfo *meminfo =
                (struct multiboot_tag_basic_meminfo *)tag;
            mem_upper = meminfo->mem_upper;
        }

        uint64_t next = (uint64_t)tag + tag->size;
        next = (next + 7) & ~7;
        tag = (struct multiboot_tag *)next;
    }

    return mem_upper > 0 ? mem_upper : 128 * 1024;
}

void kernel_main(uint32_t multiboot_info) {

    early_serial_init();
    early_serial_write("kernel entry\r\n");

    console_init();

    kprintf("iruel kernel starting...\n");
    kprintf("multiboot info at 0x%x\n", multiboot_info);

    extern uint32_t multiboot_magic;
    uint64_t mem_upper = parse_multiboot(multiboot_magic, multiboot_info);
    kprintf("upper memory: %d kb\n", (uint32_t)mem_upper);

    kprintf("initializing gdt...\n");
    gdt_init();

    kprintf("initializing idt...\n");
    idt_init();

    kprintf("initializing physical memory...\n");
    physmem_init(mem_upper);

    kprintf("initializing paging...\n");
    paging_init();

    kprintf("initializing timer...\n");
    timer_init(100);

    kprintf("initializing vfs...\n");
    vfs_init();
    ramfs_init();
    procfs_init();

    kprintf("Loading initramfs (%d files)...\n", initramfs_count);
    for (int i = 0; i < initramfs_count; i++) {
        if (initramfs_files[i].name && initramfs_files[i].data) {
            kprintf("  %s (%d bytes)\n", initramfs_files[i].name,
                    (int)initramfs_files[i].size);
            ramfs_create_file(initramfs_files[i].name,
                             initramfs_files[i].data,
                             initramfs_files[i].size);
        }
    }

    kprintf("initializing syscalls...\n");
    syscall_init();

    kprintf("initializing processes...\n");
    process_init();
    schedule_init();

    kprintf("enabling interrupts...\n");
    sti();

    kprintf("starting /bin/init...\n");
    if (process_exec("/bin/init", NULL, NULL) < 0) {
        panic("failed to execute /bin/init");
    }

    panic("init process returned");
}
