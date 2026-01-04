extern int printf(const char *fmt, ...);
extern int puts(const char *s);
extern void exit(int status);
extern int strcmp(const char *s1, const char *s2);

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

extern int uname(struct utsname *buf);

int main(int argc, char *argv[]) {
    struct utsname uts;

    if (uname(&uts) < 0) {
        puts("uname: system call failed");
        exit(1);
    }

    int all = 0;
    if (argc > 1 && strcmp(argv[1], "-a") == 0) {
        all = 1;
    }

    if (all) {

        printf("%s %s %s %s %s\n",
               uts.sysname,
               uts.nodename,
               uts.release,
               uts.version,
               uts.machine);
    } else {

        puts(uts.sysname);
    }

    exit(0);
    return 0;
}
