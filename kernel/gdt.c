#include "include/kernel.h"
#include "include/memory.h"

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_middle;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
} __attribute__((packed));

struct tss {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb_offset;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct gdt_entry gdt[7];
static struct gdt_ptr gdt_pointer;
static struct tss tss;

static uint8_t kernel_stack[4096] __attribute__((aligned(16)));

static void gdt_set_entry(int num, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt[num].base_low = base & 0xFFFF;
    gdt[num].base_middle = (base >> 16) & 0xFF;
    gdt[num].base_high = (base >> 24) & 0xFF;
    gdt[num].limit_low = limit & 0xFFFF;
    gdt[num].granularity = ((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt[num].access = access;
}

static void gdt_set_tss(int num, uint64_t base, uint32_t limit) {
    gdt[num].base_low = base & 0xFFFF;
    gdt[num].base_middle = (base >> 16) & 0xFF;
    gdt[num].base_high = (base >> 24) & 0xFF;
    gdt[num].limit_low = limit & 0xFFFF;
    gdt[num].granularity = (limit >> 16) & 0x0F;
    gdt[num].access = 0x89;

    uint32_t *high = (uint32_t *)&gdt[num + 1];
    high[0] = base >> 32;
    high[1] = 0;
}

extern void gdt_flush(uint64_t gdt_ptr);
extern void tss_flush(void);

static void load_gdt(void) {
    __asm__ volatile(
        "lgdt %0\n"
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%ax, %%ss\n"
        "pushq $0x08\n"
        "pushq $1f\n"
        "retfq\n"
        "1:\n"
        :
        : "m"(gdt_pointer)
        : "memory", "rax"
    );
}

static void load_tss(void) {
    __asm__ volatile(
        "mov $0x28, %%ax\n"
        "ltr %%ax\n"
        :
        :
        : "rax"
    );
}

void gdt_init(void) {
    gdt_pointer.limit = sizeof(gdt) - 1;
    gdt_pointer.base = (uint64_t)&gdt;

    gdt_set_entry(0, 0, 0, 0, 0);

    gdt_set_entry(1, 0, 0xFFFFF, 0x9A, 0xAF);

    gdt_set_entry(2, 0, 0xFFFFF, 0x92, 0x8F);

    gdt_set_entry(3, 0, 0xFFFFF, 0xFA, 0xAF);

    gdt_set_entry(4, 0, 0xFFFFF, 0xF2, 0x8F);

    memset(&tss, 0, sizeof(tss));
    tss.rsp0 = (uint64_t)&kernel_stack[4096];
    tss.iopb_offset = sizeof(tss);
    gdt_set_tss(5, (uint64_t)&tss, sizeof(tss) - 1);

    load_gdt();
    load_tss();
}

void gdt_set_kernel_stack(uint64_t stack) {
    tss.rsp0 = stack;
}
