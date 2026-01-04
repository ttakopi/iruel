#include "include/kernel.h"

void panic(const char *msg) {
    cli();

    kprintf("\n");
    kprintf("*** kernel panic ***\n");
    kprintf("%s\n", msg);
    kprintf("\n");
    kprintf("system halted\n");

    for (;;) {
        hlt();
    }
}
