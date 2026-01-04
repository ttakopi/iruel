#include <stdint.h>
#include <stddef.h>

extern int open(const char *path, int flags);
extern int close(int fd);
extern int64_t read(int fd, void *buf, unsigned long count);
extern int64_t write(int fd, const void *buf, unsigned long count);
extern void exit(int status);
extern int printf(const char *fmt, ...);

#define O_RDONLY 0x0000

int main(int argc, char *argv[]) {
    char buf[256];

    if (argc == 1) {
        for (;;) {
            int64_t n = read(0, buf, sizeof(buf));
            if (n <= 0) break;
            write(1, buf, (unsigned long)n);
        }
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            printf("cat: cannot open %s\n", argv[i]);
            continue;
        }
        for (;;) {
            int64_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            write(1, buf, (unsigned long)n);
        }
        close(fd);
    }

    return 0;
}
