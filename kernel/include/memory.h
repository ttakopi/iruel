#ifndef _MEMORY_H
#define _MEMORY_H

#include <stdint.h>
#include <stddef.h>

#define PAGE_SIZE       4096
#define PAGE_SHIFT      12
#define PAGE_MASK       (~(PAGE_SIZE - 1))

#define PTE_PRESENT     (1UL << 0)
#define PTE_WRITABLE    (1UL << 1)
#define PTE_USER        (1UL << 2)
#define PTE_WRITETHROUGH (1UL << 3)
#define PTE_NOCACHE     (1UL << 4)
#define PTE_ACCESSED    (1UL << 5)
#define PTE_DIRTY       (1UL << 6)
#define PTE_HUGE        (1UL << 7)
#define PTE_GLOBAL      (1UL << 8)
#define PTE_NX          (1UL << 63)

#define KERNEL_BASE     0xFFFFFFFF80000000UL
#define USER_STACK_TOP  0x00007FFFFFFFE000UL
#define USER_HEAP_START 0x0000000010000000UL
#define USER_MMAP_START 0x0000000040000000UL
#define USER_MMAP_END   0x0000700000000000UL

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4
#define PROT_NONE       0x0

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS

void *physmem_alloc_page(void);
void *physmem_alloc_pages(size_t pages);
void physmem_free_page(void *page);
void physmem_free_pages(void *page, size_t pages);
uint64_t physmem_get_total(void);
uint64_t physmem_get_free(void);

void paging_map_page(uint64_t virt, uint64_t phys, uint64_t flags);
void paging_map_page_in_space(uint64_t *pml4, uint64_t virt, uint64_t phys, uint64_t flags);
void paging_unmap_page(uint64_t virt);
uint64_t paging_get_phys(uint64_t virt);
uint64_t *paging_create_address_space(void);
uint64_t *paging_clone_address_space(uint64_t *src);
void paging_switch_address_space(uint64_t *pml4);
void paging_destroy_address_space(uint64_t *pml4);

#define PAGE_ALIGN_DOWN(addr) ((addr) & PAGE_MASK)
#define PAGE_ALIGN_UP(addr)   (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PHYS_TO_VIRT(addr)    ((void *)((uint64_t)(addr)))
#define VIRT_TO_PHYS(addr)    ((uint64_t)(addr))

void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

#endif
