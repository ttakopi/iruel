#include <stdint.h>
#include <stddef.h>

extern int printf(const char *fmt, ...);
extern int open(const char *path, int flags);
extern int close(int fd);
extern int readdir(int fd, void *dent);
extern void exit(int status);

#define O_RDONLY 0x0000
#define NAME_MAX 64

struct dirent {
    uint32_t ino;
    uint32_t type;
    char name[NAME_MAX];
};

int main(int argc, char *argv[]) {
    const char *path = "/";
    if (argc > 1) {
        path = argv[1];
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("ls: cannot open %s\n", path);
        exit(1);
    }

    struct dirent dent;
    while (readdir(fd, &dent) > 0) {
        printf("%s\n", dent.name);
    }

    close(fd);
    return 0;
}
