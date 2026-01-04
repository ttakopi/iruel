#include "include/kernel.h"
#include "include/memory.h"

#define MAX_PHYS_MEM    (1024 * 1024 * 1024UL)
#define MAX_PAGES       (MAX_PHYS_MEM / PAGE_SIZE)

static uint64_t page_bitmap[MAX_PAGES / 64];
static uint64_t total_pages = 0;
static uint64_t free_pages = 0;
static uint64_t first_free_page = 0;

static void bitmap_set(uint64_t page) {
    page_bitmap[page / 64] |= (1UL << (page % 64));
}

static void bitmap_clear(uint64_t page) {
    page_bitmap[page / 64] &= ~(1UL << (page % 64));
}

static int bitmap_test(uint64_t page) {
    return (page_bitmap[page / 64] >> (page % 64)) & 1;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = s;
    while (n--) {
        *p++ = (uint8_t)c;
    }
    return s;
}

void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = s1, *p2 = s2;
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

void physmem_init(uint64_t mem_upper_kb) {

    uint64_t total_mem = (mem_upper_kb + 1024) * 1024;
    if (total_mem > MAX_PHYS_MEM) {
        total_mem = MAX_PHYS_MEM;
    }

    total_pages = total_mem / PAGE_SIZE;
    kprintf("total physical pages: %d (%d mb)\n",
            (uint32_t)total_pages, (uint32_t)(total_mem / (1024 * 1024)));

    memset(page_bitmap, 0xFF, sizeof(page_bitmap));

    uint64_t kernel_end_addr = (uint64_t)__kernel_end;
    first_free_page = PAGE_ALIGN_UP(kernel_end_addr) / PAGE_SIZE;

    if (first_free_page < 512) {
        first_free_page = 512;
    }

    for (uint64_t i = first_free_page; i < total_pages; i++) {
        bitmap_clear(i);
        free_pages++;
    }

    kprintf("free physical pages: %d (%d mb)\n",
            (uint32_t)free_pages, (uint32_t)(free_pages * PAGE_SIZE / (1024 * 1024)));
}

void *physmem_alloc_page(void) {
    if (free_pages == 0) {
        return NULL;
    }

    for (uint64_t i = first_free_page; i < total_pages; i++) {
        if (!bitmap_test(i)) {
            bitmap_set(i);
            free_pages--;

            void *page = (void *)(i * PAGE_SIZE);
            memset(page, 0, PAGE_SIZE);
            return page;
        }
    }

    return NULL;
}

void *physmem_alloc_pages(size_t pages) {
    if (pages == 0) {
        return NULL;
    }
    if (pages == 1) {
        return physmem_alloc_page();
    }
    if (free_pages < pages) {
        return NULL;
    }

    for (uint64_t start = first_free_page; start + pages <= total_pages; start++) {
        int found = 1;
        for (uint64_t i = 0; i < pages; i++) {
            if (bitmap_test(start + i)) {
                found = 0;
                start += i;
                break;
            }
        }
        if (!found) {
            continue;
        }

        for (uint64_t i = 0; i < pages; i++) {
            bitmap_set(start + i);
        }
        free_pages -= pages;

        void *base = (void *)(start * PAGE_SIZE);
        memset(base, 0, pages * PAGE_SIZE);
        return base;
    }

    return NULL;
}

void physmem_free_page(void *page) {
    if (page == NULL) {
        return;
    }

    uint64_t page_num = (uint64_t)page / PAGE_SIZE;
    if (page_num >= total_pages || page_num < first_free_page) {
        return;
    }

    if (bitmap_test(page_num)) {
        bitmap_clear(page_num);
        free_pages++;
    }
}

void physmem_free_pages(void *page, size_t pages) {
    if (page == NULL || pages == 0) {
        return;
    }
    if (pages == 1) {
        physmem_free_page(page);
        return;
    }

    uint64_t page_num = (uint64_t)page / PAGE_SIZE;
    if (page_num >= total_pages || page_num < first_free_page) {
        return;
    }

    for (size_t i = 0; i < pages; i++) {
        uint64_t idx = page_num + i;
        if (idx >= total_pages) {
            break;
        }
        if (bitmap_test(idx)) {
            bitmap_clear(idx);
            free_pages++;
        }
    }
}

uint64_t physmem_get_total(void) {
    return total_pages * PAGE_SIZE;
}

uint64_t physmem_get_free(void) {
    return free_pages * PAGE_SIZE;
}
