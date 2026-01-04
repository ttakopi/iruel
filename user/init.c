extern int printf(const char *fmt, ...);
extern int puts(const char *s);
extern int execve(const char *path, char *const argv[], char *const envp[]);
extern void exit(int status);
extern int getpid(void);
extern int getuid(void);
extern int getgid(void);
extern int uname(void *buf);

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

int main(int argc, char *argv[], char *envp[]) {
    (void)argc;
    (void)argv;
    (void)envp;

    printf("iruel init starting (pid %d)\n", getpid());

    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("%s %s %s %s %s\n",
               uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);
    } else {
        puts("uname: system call failed");
    }

    int uid = getuid();
    int gid = getgid();
    const char *username = uid == 0 ? "root" : "user";
    const char *groupname = gid == 0 ? "root" : "users";
    printf("uid=%d(%s) gid=%d(%s)\n", uid, username, gid, groupname);

    char *shell_argv[] = { "/bin/sh", 0 };
    execve("/bin/sh", shell_argv, 0);
    printf("init: failed to exec shell\n");
    exit(1);
    return 0;
}
