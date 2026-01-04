#include "include/kernel.h"
#include "include/memory.h"

#define PML4_INDEX(addr) (((addr) >> 39) & 0x1FF)
#define PDPT_INDEX(addr) (((addr) >> 30) & 0x1FF)
#define PD_INDEX(addr)   (((addr) >> 21) & 0x1FF)
#define PT_INDEX(addr)   (((addr) >> 12) & 0x1FF)

static uint64_t *split_huge_page(uint64_t *pd, int index, uint64_t flags) {
    uint64_t entry = pd[index];
    uint64_t base = entry & 0x000FFFFFFFE00000UL;
    uint64_t pte_flags = (entry & ~PAGE_MASK) & ~PTE_HUGE;

    uint64_t *pt = physmem_alloc_page();
    if (!pt) {
        return NULL;
    }
    memset(pt, 0, PAGE_SIZE);

    for (int i = 0; i < 512; i++) {
        pt[i] = (base + (uint64_t)i * PAGE_SIZE) | pte_flags;
    }

    pd[index] = (uint64_t)pt | pte_flags | (flags & (PTE_USER | PTE_WRITABLE));
    return pt;
}

uint64_t *kernel_pml4 = NULL;

static uint64_t get_cr3(void) {
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static void set_cr3(uint64_t cr3) {
    __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
}

static void invlpg(uint64_t addr) {
    __asm__ volatile("invlpg (%0)" : : "r"(addr) : "memory");
}

static uint64_t *get_or_create_table(uint64_t *table, int index, uint64_t flags) {
    if (!(table[index] & PTE_PRESENT)) {
        void *new_table = physmem_alloc_page();
        if (!new_table) {
            return NULL;
        }
        table[index] = (uint64_t)new_table | flags | PTE_PRESENT;
    } else {

        table[index] |= (flags | PTE_PRESENT);
    }
    return (uint64_t *)(table[index] & PAGE_MASK);
}

void paging_init(void) {

    kernel_pml4 = (uint64_t *)get_cr3();

    kprintf("kernel pml4 at 0x%lx\n", (uint64_t)kernel_pml4);
}

void paging_map_page(uint64_t virt, uint64_t phys, uint64_t flags) {
    paging_map_page_in_space(kernel_pml4, virt, phys, flags);
}

void paging_map_page_in_space(uint64_t *pml4, uint64_t virt, uint64_t phys, uint64_t flags) {
    if (!pml4) {
        panic("paging_map_page_in_space: NULL pml4");
    }

    uint64_t *pdpt = get_or_create_table(pml4, PML4_INDEX(virt), PTE_WRITABLE | PTE_USER);
    if (!pdpt) {
        panic("failed to allocate pdpt");
    }

    uint64_t *pd = get_or_create_table(pdpt, PDPT_INDEX(virt), PTE_WRITABLE | PTE_USER);
    if (!pd) {
        panic("failed to allocate pd");
    }

    uint64_t pd_idx = PD_INDEX(virt);
    if (pd[pd_idx] & PTE_HUGE) {
        uint64_t *split = split_huge_page(pd, pd_idx, PTE_WRITABLE | PTE_USER);
        if (!split) {
            panic("failed to split huge page");
        }
    }

    uint64_t *pt = get_or_create_table(pd, pd_idx, PTE_WRITABLE | PTE_USER);
    if (!pt) {
        panic("failed to allocate pt");
    }

    pt[PT_INDEX(virt)] = (phys & PAGE_MASK) | flags | PTE_PRESENT;

    invlpg(virt);
}

void paging_unmap_page(uint64_t virt) {
    uint64_t *pml4 = kernel_pml4;

    if (!(pml4[PML4_INDEX(virt)] & PTE_PRESENT)) return;
    uint64_t *pdpt = (uint64_t *)(pml4[PML4_INDEX(virt)] & PAGE_MASK);

    if (!(pdpt[PDPT_INDEX(virt)] & PTE_PRESENT)) return;
    uint64_t *pd = (uint64_t *)(pdpt[PDPT_INDEX(virt)] & PAGE_MASK);

    if (!(pd[PD_INDEX(virt)] & PTE_PRESENT)) return;
    uint64_t *pt = (uint64_t *)(pd[PD_INDEX(virt)] & PAGE_MASK);

    pt[PT_INDEX(virt)] = 0;

    invlpg(virt);
}

uint64_t paging_get_phys(uint64_t virt) {
    uint64_t *pml4 = kernel_pml4;

    if (!(pml4[PML4_INDEX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pdpt = (uint64_t *)(pml4[PML4_INDEX(virt)] & PAGE_MASK);

    if (!(pdpt[PDPT_INDEX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pd = (uint64_t *)(pdpt[PDPT_INDEX(virt)] & PAGE_MASK);

    if (pd[PD_INDEX(virt)] & PTE_HUGE) {
        return (pd[PD_INDEX(virt)] & 0x000FFFFFFFFFE000UL) | (virt & 0x1FFFFF);
    }

    if (!(pd[PD_INDEX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pt = (uint64_t *)(pd[PD_INDEX(virt)] & PAGE_MASK);

    if (!(pt[PT_INDEX(virt)] & PTE_PRESENT)) return 0;

    return (pt[PT_INDEX(virt)] & PAGE_MASK) | (virt & 0xFFF);
}

uint64_t *paging_create_address_space(void) {
    uint64_t *new_pml4 = physmem_alloc_page();
    if (!new_pml4) {
        return NULL;
    }

    memcpy(new_pml4, kernel_pml4, PAGE_SIZE);

    return new_pml4;
}

uint64_t *paging_clone_address_space(uint64_t *src) {
    if (!src) {
        return NULL;
    }

    uint64_t *dst = physmem_alloc_page();
    if (!dst) {
        return NULL;
    }
    memset(dst, 0, PAGE_SIZE);

    for (int i = 256; i < 512; i++) {
        dst[i] = src[i];
    }

    for (int i = 0; i < 256; i++) {
        if (!(src[i] & PTE_PRESENT)) {
            continue;
        }
        uint64_t *src_pdpt = (uint64_t *)(src[i] & PAGE_MASK);
        uint64_t *dst_pdpt = physmem_alloc_page();
        if (!dst_pdpt) {
            paging_destroy_address_space(dst);
            return NULL;
        }
        memset(dst_pdpt, 0, PAGE_SIZE);
        dst[i] = (uint64_t)dst_pdpt | (src[i] & ~PAGE_MASK);

        for (int j = 0; j < 512; j++) {
            if (!(src_pdpt[j] & PTE_PRESENT)) {
                continue;
            }
            if (src_pdpt[j] & PTE_HUGE) {
                dst_pdpt[j] = src_pdpt[j];
                continue;
            }
            uint64_t *src_pd = (uint64_t *)(src_pdpt[j] & PAGE_MASK);
            uint64_t *dst_pd = physmem_alloc_page();
            if (!dst_pd) {
                paging_destroy_address_space(dst);
                return NULL;
            }
            memset(dst_pd, 0, PAGE_SIZE);
            dst_pdpt[j] = (uint64_t)dst_pd | (src_pdpt[j] & ~PAGE_MASK);

            for (int k = 0; k < 512; k++) {
                if (!(src_pd[k] & PTE_PRESENT)) {
                    continue;
                }
                if (src_pd[k] & PTE_HUGE) {
                    dst_pd[k] = src_pd[k];
                    continue;
                }
                uint64_t *src_pt = (uint64_t *)(src_pd[k] & PAGE_MASK);
                uint64_t *dst_pt = physmem_alloc_page();
                if (!dst_pt) {
                    paging_destroy_address_space(dst);
                    return NULL;
                }
                memset(dst_pt, 0, PAGE_SIZE);
                dst_pd[k] = (uint64_t)dst_pt | (src_pd[k] & ~PAGE_MASK);

                for (int l = 0; l < 512; l++) {
                    if (!(src_pt[l] & PTE_PRESENT)) {
                        continue;
                    }
                    uint64_t phys = src_pt[l] & PAGE_MASK;
                    uint64_t flags = src_pt[l] & ~PAGE_MASK;
                    void *page = physmem_alloc_page();
                    if (!page) {
                        paging_destroy_address_space(dst);
                        return NULL;
                    }
                    memcpy(page, (void *)phys, PAGE_SIZE);
                    dst_pt[l] = (uint64_t)page | flags;
                }
            }
        }
    }

    return dst;
}

void paging_switch_address_space(uint64_t *pml4) {
    set_cr3((uint64_t)pml4);
}

void paging_destroy_address_space(uint64_t *pml4) {
    if (pml4 == kernel_pml4) {
        return;
    }

    for (int i = 0; i < 256; i++) {
        if (pml4[i] & PTE_PRESENT) {
            uint64_t *pdpt = (uint64_t *)(pml4[i] & PAGE_MASK);
            for (int j = 0; j < 512; j++) {
                if (pdpt[j] & PTE_PRESENT && !(pdpt[j] & PTE_HUGE)) {
                    uint64_t *pd = (uint64_t *)(pdpt[j] & PAGE_MASK);
                    for (int k = 0; k < 512; k++) {
                        if (pd[k] & PTE_PRESENT && !(pd[k] & PTE_HUGE)) {
                            physmem_free_page((void *)(pd[k] & PAGE_MASK));
                        }
                    }
                    physmem_free_page(pd);
                }
            }
            physmem_free_page(pdpt);
        }
    }

    physmem_free_page(pml4);
}
