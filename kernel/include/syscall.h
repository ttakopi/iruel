#ifndef _SYSCALL_H
#define _SYSCALL_H

#include <stdint.h>
#include <stddef.h>

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
#define SYS_CHMOD       17
#define SYS_MMAP        18
#define SYS_MUNMAP      19

#define SYSCALL_MAX     20

struct dirent;

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

void syscall_init(void);

int64_t syscall_handler(uint64_t num, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5);

int sys_exit(int status);
int sys_fork(void);
int64_t sys_read(int fd, void *buf, size_t count);
int64_t sys_write(int fd, const void *buf, size_t count);
int sys_open(const char *path, int flags);
int sys_close(int fd);
int sys_execve(const char *path, char *const argv[], char *const envp[]);
int sys_getpid(void);
int sys_getppid(void);
int sys_getuid(void);
int sys_getgid(void);
int sys_uname(struct utsname *buf);
int64_t sys_brk(uint64_t addr);
int sys_waitpid(int pid, int *status, int options);
int sys_pipe(int fds[2]);
int sys_dup2(int oldfd, int newfd);
int sys_readdir(int fd, struct dirent *dent);
int sys_chmod(const char *path, uint32_t mode);
void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, uint64_t offset);
int sys_munmap(void *addr, size_t length);

#endif
