.section .note.Xen, "a"
.align 4
.long 4
.long 12
.long 18
.asciz "Xen"
.align 4
.long _start
.long 0
.long 0

.set MULTIBOOT2_MAGIC,    0xe85250d6
.set MULTIBOOT2_ARCH,     0
.set HEADER_LENGTH,       (multiboot_header_end - multiboot_header_start)
.set CHECKSUM,            -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH + HEADER_LENGTH)

.section .multiboot, "a"
.align 8
multiboot_header_start:
    .long MULTIBOOT2_MAGIC
    .long MULTIBOOT2_ARCH
    .long HEADER_LENGTH
    .long CHECKSUM

    .align 8
    .short 3
    .short 0
    .long 12
    .long _start

    .align 8
    .short 5
    .short 0
    .long 20
    .long 80
    .long 25
    .long 0

    .align 8
    .short 0
    .short 0
    .long 8
multiboot_header_end:

.section .data
.global multiboot_magic
multiboot_magic:
    .long 0

.section .bss
.align 4096

pml4:
    .skip 4096
pdpt:
    .skip 4096
pd:
    .skip 4096

.align 16
stack_bottom:
    .skip 16384
stack_top:

.section .rodata
.align 8

gdt64:
    .quad 0
gdt64_code:
    .quad 0x00af9a000000ffff
gdt64_data:
    .quad 0x00af92000000ffff
gdt64_user_code:
    .quad 0x00affa000000ffff
gdt64_user_data:
    .quad 0x00aff2000000ffff
gdt64_tss:
    .quad 0
    .quad 0
gdt64_end:

gdt64_pointer:
    .word gdt64_end - gdt64 - 1
    .quad gdt64

.section .text
.code32

.global _start
.type _start, @function
_start:

    cli

    mov $0x3F9, %dx
    mov $0x00, %al
    out %al, %dx
    mov $0x3FB, %dx
    mov $0x80, %al
    out %al, %dx
    mov $0x3F8, %dx
    mov $0x03, %al
    out %al, %dx
    mov $0x3F9, %dx
    mov $0x00, %al
    out %al, %dx
    mov $0x3FB, %dx
    mov $0x03, %al
    out %al, %dx
    mov $0x3FA, %dx
    mov $0x01, %al
    out %al, %dx
    mov $0x3FC, %dx
    mov $0x0B, %al
    out %al, %dx

    mov %eax, multiboot_magic
    mov %ebx, %edi

    mov $stack_top, %esp

    pushfl
    pop %eax
    mov %eax, %ecx
    xor $0x200000, %eax
    push %eax
    popfl
    pushfl
    pop %eax
    push %ecx
    popfl
    cmp %ecx, %eax
    je no_cpuid

    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb no_long_mode

    mov $0x80000001, %eax
    cpuid
    test $0x20000000, %edx
    jz no_long_mode

    mov $pdpt, %eax
    or $0x03, %eax
    mov %eax, pml4

    mov $pd, %eax
    or $0x03, %eax
    mov %eax, pdpt

    mov $pd, %edi
    mov $0x83, %eax
    mov $512, %ecx
1:
    mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop 1b

    mov $pml4, %eax
    mov %eax, %cr3

    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4

    mov $0xc0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr

    mov %cr0, %eax
    or $0x80000001, %eax
    mov %eax, %cr0

    lgdt gdt64_pointer

    ljmp $0x08, $long_mode_entry

no_cpuid:
no_long_mode:

    hlt
    jmp no_long_mode

.code64

long_mode_entry:

    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    mov $stack_top, %rsp

    movl %edi, %edi

    out %al, %dx

    call kernel_main

halt:
    cli
    hlt
    jmp halt

.size _start, . - _start
