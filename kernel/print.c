#include "include/kernel.h"
#include <stdarg.h>

#define VGA_ADDR    0xB8000
#define VGA_WIDTH   80
#define VGA_HEIGHT  25

#define VGA_BLACK       0
#define VGA_BLUE        1
#define VGA_GREEN       2
#define VGA_CYAN        3
#define VGA_RED         4
#define VGA_MAGENTA     5
#define VGA_BROWN       6
#define VGA_LIGHT_GRAY  7

#define VGA_COLOR(fg, bg) ((bg << 4) | fg)
#define VGA_ENTRY(c, color) ((uint16_t)(c) | ((uint16_t)(color) << 8))

static uint16_t *vga_buffer = (uint16_t *)VGA_ADDR;
static int cursor_x = 0;
static int cursor_y = 0;
static uint8_t vga_color = VGA_COLOR(VGA_LIGHT_GRAY, VGA_BLACK);

static void update_cursor(void) {
    uint16_t pos = cursor_y * VGA_WIDTH + cursor_x;
    outb(0x3D4, 0x0F);
    outb(0x3D5, (uint8_t)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

static void scroll(void) {
    for (int y = 0; y < VGA_HEIGHT - 1; y++) {
        for (int x = 0; x < VGA_WIDTH; x++) {
            vga_buffer[y * VGA_WIDTH + x] = vga_buffer[(y + 1) * VGA_WIDTH + x];
        }
    }
    for (int x = 0; x < VGA_WIDTH; x++) {
        vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = VGA_ENTRY(' ', vga_color);
    }
}

#define COM1 0x3F8

static void serial_init(void) {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0x01);
    outb(COM1 + 4, 0x0B);
}

static void serial_putchar(char c) {

    while ((inb(COM1 + 5) & 0x20) == 0);
    outb(COM1, c);
}

static void putchar(char c) {

    serial_putchar(c);

    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
    } else if (c == '\r') {
        cursor_x = 0;
    } else if (c == '\t') {
        cursor_x = (cursor_x + 8) & ~7;
    } else if (c == '\b') {
        if (cursor_x > 0) {
            cursor_x--;
            vga_buffer[cursor_y * VGA_WIDTH + cursor_x] = VGA_ENTRY(' ', vga_color);
        }
    } else {
        vga_buffer[cursor_y * VGA_WIDTH + cursor_x] = VGA_ENTRY(c, vga_color);
        cursor_x++;
    }

    if (cursor_x >= VGA_WIDTH) {
        cursor_x = 0;
        cursor_y++;
    }

    while (cursor_y >= VGA_HEIGHT) {
        scroll();
        cursor_y--;
    }

    update_cursor();
}

void kputs(const char *s) {
    while (*s) {
        putchar(*s++);
    }
}

static void print_uint(uint64_t val, int base, int width, char pad) {
    char buf[32];
    int i = 0;
    const char *digits = "0123456789abcdef";

    if (val == 0) {
        buf[i++] = '0';
    } else {
        while (val > 0) {
            buf[i++] = digits[val % base];
            val /= base;
        }
    }

    while (i < width) {
        buf[i++] = pad;
    }

    while (i > 0) {
        putchar(buf[--i]);
    }
}

static void print_int(int64_t val, int width, char pad) {
    if (val < 0) {
        putchar('-');
        val = -val;
        if (width > 0) width--;
    }
    print_uint((uint64_t)val, 10, width, pad);
}

void kprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    while (*fmt) {
        if (*fmt != '%') {
            putchar(*fmt++);
            continue;
        }

        fmt++;
        if (*fmt == '\0') break;

        char pad = ' ';
        int width = 0;
        if (*fmt == '0') {
            pad = '0';
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }

        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
            if (*fmt == 'l') {
                fmt++;
            }
        }

        switch (*fmt) {
            case 'd':
            case 'i':
                if (is_long) {
                    print_int(va_arg(ap, int64_t), width, pad);
                } else {
                    print_int(va_arg(ap, int), width, pad);
                }
                break;
            case 'u':
                if (is_long) {
                    print_uint(va_arg(ap, uint64_t), 10, width, pad);
                } else {
                    print_uint(va_arg(ap, unsigned int), 10, width, pad);
                }
                break;
            case 'x':
                if (is_long) {
                    print_uint(va_arg(ap, uint64_t), 16, width, pad);
                } else {
                    print_uint(va_arg(ap, unsigned int), 16, width, pad);
                }
                break;
            case 'p':
                kputs("0x");
                print_uint(va_arg(ap, uint64_t), 16, 16, '0');
                break;
            case 's': {
                const char *s = va_arg(ap, const char *);
                if (s == NULL) s = "(null)";
                kputs(s);
                break;
            }
            case 'c':
                putchar((char)va_arg(ap, int));
                break;
            case '%':
                putchar('%');
                break;
            default:
                putchar('%');
                putchar(*fmt);
                break;
        }
        fmt++;
    }

    va_end(ap);
}

void console_clear(void) {
    serial_init();
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        vga_buffer[i] = VGA_ENTRY(' ', vga_color);
    }
    cursor_x = 0;
    cursor_y = 0;
    update_cursor();
}
