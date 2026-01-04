#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#define SYS_EXIT        0
#define SYS_FORK        1
#define SYS_READ        2
#define SYS_WRITE       3
#define SYS_OPEN        4
#define SYS_CLOSE       5
#define SYS_EXECVE      6
#define SYS_GETPID      7
#define SYS_GETPPID     8
#define SYS_GETUID      9
#define SYS_GETGID      10
#define SYS_UNAME       11
#define SYS_BRK         12
#define SYS_WAITPID     13
#define SYS_PIPE        14
#define SYS_DUP2        15
#define SYS_READDIR     16

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

static inline int64_t syscall0(int num) {
    int64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline int64_t syscall1(int num, uint64_t arg1) {
    int64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline int64_t syscall2(int num, uint64_t arg1, uint64_t arg2) {
    int64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline int64_t syscall3(int num, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    int64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void exit(int status) {
    syscall1(SYS_EXIT, status);
    for (;;);
}

int fork(void) {
    return syscall0(SYS_FORK);
}

int64_t read(int fd, void *buf, size_t count) {
    return syscall3(SYS_READ, fd, (uint64_t)buf, count);
}

int64_t write(int fd, const void *buf, size_t count) {
    return syscall3(SYS_WRITE, fd, (uint64_t)buf, count);
}

int open(const char *path, int flags) {
    return syscall2(SYS_OPEN, (uint64_t)path, flags);
}

int close(int fd) {
    return syscall1(SYS_CLOSE, fd);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    return syscall3(SYS_EXECVE, (uint64_t)path, (uint64_t)argv, (uint64_t)envp);
}

int getpid(void) {
    return syscall0(SYS_GETPID);
}

int getppid(void) {
    return syscall0(SYS_GETPPID);
}

int getuid(void) {
    return syscall0(SYS_GETUID);
}

int getgid(void) {
    return syscall0(SYS_GETGID);
}

int uname(struct utsname *buf) {
    return syscall1(SYS_UNAME, (uint64_t)buf);
}

int waitpid(int pid, int *status, int options) {
    return syscall3(SYS_WAITPID, pid, (uint64_t)status, options);
}

int pipe(int fds[2]) {
    return syscall1(SYS_PIPE, (uint64_t)fds);
}

int dup2(int oldfd, int newfd) {
    return syscall2(SYS_DUP2, oldfd, newfd);
}

int readdir(int fd, void *dent) {
    return syscall2(SYS_READDIR, fd, (uint64_t)dent);
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i]; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return *(unsigned char *)s1 - *(unsigned char *)s2;
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

int puts(const char *s) {
    size_t len = strlen(s);
    write(1, s, len);
    write(1, "\n", 1);
    return len + 1;
}

int putchar(int c) {
    char ch = c;
    write(1, &ch, 1);
    return c;
}

static void print_uint(uint64_t val, int base) {
    char buf[32];
    int i = 0;
    const char *digits = "0123456789abcdef";

    if (val == 0) {
        putchar('0');
        return;
    }

    while (val > 0) {
        buf[i++] = digits[val % base];
        val /= base;
    }

    while (i > 0) {
        putchar(buf[--i]);
    }
}

static void print_int(int64_t val) {
    if (val < 0) {
        putchar('-');
        val = -val;
    }
    print_uint((uint64_t)val, 10);
}

int printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    int count = 0;

    while (*fmt) {
        if (*fmt != '%') {
            putchar(*fmt++);
            count++;
            continue;
        }

        fmt++;
        if (*fmt == '\0') break;

        switch (*fmt) {
            case 'd':
            case 'i':
                print_int(va_arg(ap, int));
                break;
            case 'u':
                print_uint(va_arg(ap, unsigned int), 10);
                break;
            case 'x':
                print_uint(va_arg(ap, unsigned int), 16);
                break;
            case 'l':
                fmt++;
                if (*fmt == 'd') {
                    print_int(va_arg(ap, int64_t));
                } else if (*fmt == 'u') {
                    print_uint(va_arg(ap, uint64_t), 10);
                } else if (*fmt == 'x') {
                    print_uint(va_arg(ap, uint64_t), 16);
                }
                break;
            case 's': {
                const char *s = va_arg(ap, const char *);
                if (!s) s = "(null)";
                while (*s) {
                    putchar(*s++);
                    count++;
                }
                break;
            }
            case 'c':
                putchar(va_arg(ap, int));
                count++;
                break;
            case '%':
                putchar('%');
                count++;
                break;
            default:
                putchar('%');
                putchar(*fmt);
                count += 2;
                break;
        }
        fmt++;
    }

    va_end(ap);
    return count;
}

char *gets(char *buf, int size) {
    int i = 0;
    char c;

    while (i < size - 1) {
        if (read(0, &c, 1) <= 0) break;
        if (c == '\n') break;
        if (c == '\b' && i > 0) {
            i--;
            continue;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return buf;
}
