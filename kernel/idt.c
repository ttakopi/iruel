#include "include/kernel.h"
#include "include/memory.h"
#include "include/process.h"

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry idt[256];
static struct idt_ptr idt_pointer;

extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);

extern void irq0(void);
extern void irq1(void);
extern void irq2(void);
extern void irq3(void);
extern void irq4(void);
extern void irq5(void);
extern void irq6(void);
extern void irq7(void);
extern void irq8(void);
extern void irq9(void);
extern void irq10(void);
extern void irq11(void);
extern void irq12(void);
extern void irq13(void);
extern void irq14(void);
extern void irq15(void);

extern void isr128(void);

static const char *exception_messages[] = {
    "Division By Zero",
    "Debug",
    "Non Maskable Interrupt",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid TSS",
    "Segment Not Present",
    "Stack Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved",
    "x87 Floating Point Exception",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating Point Exception",
    "Virtualization Exception",
    "Control Protection Exception",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Hypervisor Injection Exception",
    "VMM Communication Exception",
    "Security Exception",
    "Reserved"
};

static void idt_set_entry(int num, uint64_t handler, uint16_t selector, uint8_t ist, uint8_t type_attr) {
    idt[num].offset_low = handler & 0xFFFF;
    idt[num].offset_mid = (handler >> 16) & 0xFFFF;
    idt[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
    idt[num].selector = selector;
    idt[num].ist = ist;
    idt[num].type_attr = type_attr;
    idt[num].reserved = 0;
}

static void pic_remap(void) {

    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    io_wait();

    outb(0x21, 0x20);
    outb(0xA1, 0x28);
    io_wait();

    outb(0x21, 0x04);
    outb(0xA1, 0x02);
    io_wait();

    outb(0x21, 0x01);
    outb(0xA1, 0x01);
    io_wait();

    outb(0x21, 0xFC);
    outb(0xA1, 0xFF);
}

void idt_init(void) {
    idt_pointer.limit = sizeof(idt) - 1;
    idt_pointer.base = (uint64_t)&idt;

    memset(&idt, 0, sizeof(idt));

    pic_remap();

    idt_set_entry(0, (uint64_t)isr0, 0x08, 0, 0x8E);
    idt_set_entry(1, (uint64_t)isr1, 0x08, 0, 0x8E);
    idt_set_entry(2, (uint64_t)isr2, 0x08, 0, 0x8E);
    idt_set_entry(3, (uint64_t)isr3, 0x08, 0, 0x8E);
    idt_set_entry(4, (uint64_t)isr4, 0x08, 0, 0x8E);
    idt_set_entry(5, (uint64_t)isr5, 0x08, 0, 0x8E);
    idt_set_entry(6, (uint64_t)isr6, 0x08, 0, 0x8E);
    idt_set_entry(7, (uint64_t)isr7, 0x08, 0, 0x8E);
    idt_set_entry(8, (uint64_t)isr8, 0x08, 0, 0x8E);
    idt_set_entry(9, (uint64_t)isr9, 0x08, 0, 0x8E);
    idt_set_entry(10, (uint64_t)isr10, 0x08, 0, 0x8E);
    idt_set_entry(11, (uint64_t)isr11, 0x08, 0, 0x8E);
    idt_set_entry(12, (uint64_t)isr12, 0x08, 0, 0x8E);
    idt_set_entry(13, (uint64_t)isr13, 0x08, 0, 0x8E);
    idt_set_entry(14, (uint64_t)isr14, 0x08, 0, 0x8E);
    idt_set_entry(15, (uint64_t)isr15, 0x08, 0, 0x8E);
    idt_set_entry(16, (uint64_t)isr16, 0x08, 0, 0x8E);
    idt_set_entry(17, (uint64_t)isr17, 0x08, 0, 0x8E);
    idt_set_entry(18, (uint64_t)isr18, 0x08, 0, 0x8E);
    idt_set_entry(19, (uint64_t)isr19, 0x08, 0, 0x8E);
    idt_set_entry(20, (uint64_t)isr20, 0x08, 0, 0x8E);
    idt_set_entry(21, (uint64_t)isr21, 0x08, 0, 0x8E);
    idt_set_entry(22, (uint64_t)isr22, 0x08, 0, 0x8E);
    idt_set_entry(23, (uint64_t)isr23, 0x08, 0, 0x8E);
    idt_set_entry(24, (uint64_t)isr24, 0x08, 0, 0x8E);
    idt_set_entry(25, (uint64_t)isr25, 0x08, 0, 0x8E);
    idt_set_entry(26, (uint64_t)isr26, 0x08, 0, 0x8E);
    idt_set_entry(27, (uint64_t)isr27, 0x08, 0, 0x8E);
    idt_set_entry(28, (uint64_t)isr28, 0x08, 0, 0x8E);
    idt_set_entry(29, (uint64_t)isr29, 0x08, 0, 0x8E);
    idt_set_entry(30, (uint64_t)isr30, 0x08, 0, 0x8E);
    idt_set_entry(31, (uint64_t)isr31, 0x08, 0, 0x8E);

    idt_set_entry(32, (uint64_t)irq0, 0x08, 0, 0x8E);
    idt_set_entry(33, (uint64_t)irq1, 0x08, 0, 0x8E);
    idt_set_entry(34, (uint64_t)irq2, 0x08, 0, 0x8E);
    idt_set_entry(35, (uint64_t)irq3, 0x08, 0, 0x8E);
    idt_set_entry(36, (uint64_t)irq4, 0x08, 0, 0x8E);
    idt_set_entry(37, (uint64_t)irq5, 0x08, 0, 0x8E);
    idt_set_entry(38, (uint64_t)irq6, 0x08, 0, 0x8E);
    idt_set_entry(39, (uint64_t)irq7, 0x08, 0, 0x8E);
    idt_set_entry(40, (uint64_t)irq8, 0x08, 0, 0x8E);
    idt_set_entry(41, (uint64_t)irq9, 0x08, 0, 0x8E);
    idt_set_entry(42, (uint64_t)irq10, 0x08, 0, 0x8E);
    idt_set_entry(43, (uint64_t)irq11, 0x08, 0, 0x8E);
    idt_set_entry(44, (uint64_t)irq12, 0x08, 0, 0x8E);
    idt_set_entry(45, (uint64_t)irq13, 0x08, 0, 0x8E);
    idt_set_entry(46, (uint64_t)irq14, 0x08, 0, 0x8E);
    idt_set_entry(47, (uint64_t)irq15, 0x08, 0, 0x8E);

    idt_set_entry(128, (uint64_t)isr128, 0x08, 0, 0xEE);

    __asm__ volatile("lidt %0" : : "m"(idt_pointer));
}

static void (*irq_handlers[16])(void) = { 0 };
static int irq_user = 0;

int irq_from_user(void) {
    return irq_user;
}

void irq_register_handler(int irq, void (*handler)(void)) {
    if (irq >= 0 && irq < 16) {
        irq_handlers[irq] = handler;
    }
}

void exception_handler(cpu_context_t *ctx) {
    if (ctx->int_no < 32) {
        kprintf("\n*** EXCEPTION: %s ***\n", exception_messages[ctx->int_no]);
        kprintf("Error code: 0x%lx\n", ctx->err_code);
        kprintf("RIP: 0x%lx  RSP: 0x%lx\n", ctx->rip, ctx->rsp);
        kprintf("RAX: 0x%lx  RBX: 0x%lx  RCX: 0x%lx\n", ctx->rax, ctx->rbx, ctx->rcx);
        kprintf("RDX: 0x%lx  RSI: 0x%lx  RDI: 0x%lx\n", ctx->rdx, ctx->rsi, ctx->rdi);
        kprintf("CS: 0x%lx  SS: 0x%lx  RFLAGS: 0x%lx\n", ctx->cs, ctx->ss, ctx->rflags);

        if (ctx->int_no == 14) {
            uint64_t cr2;
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            kprintf("Page fault address: 0x%lx\n", cr2);
        }

        panic("Unhandled exception");
    }
}

void irq_handler(cpu_context_t *ctx) {
    int irq = ctx->int_no - 32;

    if (irq == 0) {
        outb(0x20, 0x20);
    }

    irq_user = ((ctx->cs & 3) == 3);

    if (irq >= 0 && irq < 16 && irq_handlers[irq]) {
        irq_handlers[irq]();
    }

    irq_user = 0;

    if (irq != 0) {
        if (irq >= 8) {
            outb(0xA0, 0x20);
        }
        outb(0x20, 0x20);
    }
}
