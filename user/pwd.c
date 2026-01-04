#include <stdint.h>
#include <stddef.h>

extern int64_t write(int fd, const void *buf, unsigned long count);

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    write(1, "/\n", 2);
    return 0;
}
