#include "include/kernel.h"
#include "include/memory.h"
#include "include/process.h"
#include "include/syscall.h"
#include "include/fs.h"
#include "include/errno.h"
#include "include/pipe.h"

static void serial_putchar(char c) {
    while ((inb(0x3F8 + 5) & 0x20) == 0) {
    }
    outb(0x3F8, c);
}

static char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

typedef int64_t (*syscall_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static syscall_fn syscall_table[SYSCALL_MAX];
extern process_t processes[];

int sys_exit(int status) {
    kprintf("[pid %d] exit(%d)\n", process_getpid(), status);
    process_exit(status);

    return 0;
}

int sys_fork(void) {
    return process_fork();
}

int64_t sys_read(int fd, void *buf, size_t count) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (fd < 0 || fd >= MAX_FDS) return -EBADF;
    if (!proc->fds[fd].file) return -EBADF;

    return vfs_read(proc->fds[fd].file, buf, count);
}

int64_t sys_write(int fd, const void *buf, size_t count) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (fd < 0 || fd >= MAX_FDS) return -EBADF;
    if (!proc->fds[fd].file) {
        if (fd == 1 || fd == 2) {
            const char *p = (const char *)buf;
            for (size_t i = 0; i < count; i++) {
                serial_putchar(p[i]);
            }
            return count;
        }
        return -EBADF;
    }

    if (!proc->fds[fd].file->ops || !proc->fds[fd].file->ops->write) {
        if (fd == 1 || fd == 2) {
            const char *p = (const char *)buf;
            for (size_t i = 0; i < count; i++) {
                serial_putchar(p[i]);
            }
            return count;
        }
        return -ENOSYS;
    }

    return vfs_write(proc->fds[fd].file, buf, count);
}

int sys_open(const char *path, int flags) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    int fd = -1;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!proc->fds[i].file) {
            fd = i;
            break;
        }
    }
    if (fd < 0) return -EMFILE;

    file_t *file = vfs_open(path, flags);
    if (!file) return -ENOENT;

    proc->fds[fd].file = file;
    proc->fds[fd].flags = flags;

    return fd;
}

int sys_close(int fd) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (fd < 0 || fd >= MAX_FDS) return -EBADF;
    if (!proc->fds[fd].file) return -EBADF;

    vfs_close(proc->fds[fd].file);
    proc->fds[fd].file = NULL;
    proc->fds[fd].flags = 0;

    return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
    return process_exec(path, argv, envp);
}

int sys_getpid(void) {
    return process_getpid();
}

int sys_getppid(void) {
    return process_getppid();
}

int sys_getuid(void) {
    process_t *proc = process_current();
    return proc ? proc->uid : 0;
}

int sys_getgid(void) {
    process_t *proc = process_current();
    return proc ? proc->gid : 0;
}

int sys_uname(struct utsname *buf) {
    if (!buf) return -EFAULT;

    strcpy(buf->sysname, KERNEL_NAME);
    strcpy(buf->nodename, "localhost");
    strcpy(buf->release, KERNEL_RELEASE);
    strcpy(buf->version, KERNEL_VERSION);
    strcpy(buf->machine, "x86_64");

    return 0;
}

int64_t sys_brk(uint64_t addr) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (addr == 0) {

        return proc->heap_end;
    }

    if (addr < proc->heap_start) {
        return -ENOMEM;
    }

    uint64_t old_end = proc->heap_end;
    uint64_t new_end = PAGE_ALIGN_UP(addr);

    for (uint64_t page = PAGE_ALIGN_UP(old_end); page < new_end; page += PAGE_SIZE) {
        void *phys = physmem_alloc_page();
        if (!phys) {
            return -ENOMEM;
        }
        paging_map_page_in_space(proc->page_table, page, (uint64_t)phys,
                                 PTE_USER | PTE_WRITABLE);
    }

    proc->heap_end = new_end;
    return new_end;
}

int sys_waitpid(int pid, int *status, int options) {
    (void)options;
    (void)status;

    process_t *parent = process_current();
    if (!parent) return -ESRCH;

    for (;;) {
        int has_child = 0;
        for (int i = 0; i < MAX_PROCESSES; i++) {
            process_t *proc = &processes[i];
            if (proc->state == PROC_UNUSED) {
                continue;
            }
            if (proc->ppid != parent->pid) {
                continue;
            }
            has_child = 1;
            if (proc->state == PROC_ZOMBIE) {
                if (pid == -1 || pid == proc->pid) {
                    int child_pid = proc->pid;
                    paging_destroy_address_space(proc->page_table);
                    proc->state = PROC_UNUSED;
                    return child_pid;
                }
            }
        }
        if (!has_child) {
            return -ECHILD;
        }

        parent->wait_type = WAIT_CHILD;
        parent->wait_pid = pid;
        parent->state = PROC_BLOCKED;
        schedule();
    }
}

int sys_pipe(int fds[2]) {
    if (!fds) return -EFAULT;
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    file_t *rf = NULL;
    file_t *wf = NULL;
    int ret = pipe_create(&rf, &wf);
    if (ret < 0) return ret;

    int fd0 = -1;
    int fd1 = -1;
    for (int i = 0; i < MAX_FDS; i++) {
        if (!proc->fds[i].file) {
            if (fd0 < 0) {
                fd0 = i;
            } else {
                fd1 = i;
                break;
            }
        }
    }
    if (fd0 < 0 || fd1 < 0) {
        vfs_close(rf);
        vfs_close(wf);
        return -EMFILE;
    }

    proc->fds[fd0].file = rf;
    proc->fds[fd0].flags = rf->flags;
    proc->fds[fd1].file = wf;
    proc->fds[fd1].flags = wf->flags;

    fds[0] = fd0;
    fds[1] = fd1;
    return 0;
}

int sys_dup2(int oldfd, int newfd) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;
    if (oldfd < 0 || oldfd >= MAX_FDS) return -EBADF;
    if (newfd < 0 || newfd >= MAX_FDS) return -EBADF;
    if (!proc->fds[oldfd].file) return -EBADF;

    if (oldfd == newfd) {
        return newfd;
    }

    if (proc->fds[newfd].file) {
        vfs_close(proc->fds[newfd].file);
        proc->fds[newfd].file = NULL;
        proc->fds[newfd].flags = 0;
    }

    proc->fds[newfd].file = proc->fds[oldfd].file;
    proc->fds[newfd].flags = proc->fds[oldfd].flags;
    proc->fds[newfd].file->refcount++;

    return newfd;
}

int sys_readdir(int fd, struct dirent *dent) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (fd < 0 || fd >= MAX_FDS) return -EBADF;
    if (!proc->fds[fd].file) return -EBADF;
    return vfs_readdir(proc->fds[fd].file, dent);
}

int64_t syscall_handler(uint64_t num, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    if (num >= SYSCALL_MAX) {
        return -ENOSYS;
    }

    if (syscall_table[num]) {
        return syscall_table[num](arg1, arg2, arg3, arg4, arg5);
    }

    return -ENOSYS;
}

static int64_t wrap_exit(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    sys_exit((int)a1);
    return 0;
}

static int64_t wrap_fork(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_fork();
}

static int64_t wrap_read(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_read((int)a1, (void *)a2, (size_t)a3);
}

static int64_t wrap_write(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_write((int)a1, (const void *)a2, (size_t)a3);
}

static int64_t wrap_open(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_open((const char *)a1, (int)a2);
}

static int64_t wrap_close(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_close((int)a1);
}

static int64_t wrap_execve(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_execve((const char *)a1, (char *const *)a2, (char *const *)a3);
}

static int64_t wrap_getpid(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_getpid();
}

static int64_t wrap_getppid(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_getppid();
}

static int64_t wrap_getuid(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_getuid();
}

static int64_t wrap_getgid(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_getgid();
}

static int64_t wrap_uname(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_uname((struct utsname *)a1);
}

static int64_t wrap_brk(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_brk(a1);
}

static int64_t wrap_waitpid(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    return sys_waitpid((int)a1, (int *)a2, (int)a3);
}

static int64_t wrap_pipe(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    return sys_pipe((int *)a1);
}

static int64_t wrap_dup2(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_dup2((int)a1, (int)a2);
}

static int64_t wrap_readdir(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_readdir((int)a1, (struct dirent *)a2);
}

int sys_chmod(const char *path, uint32_t mode) {
    if (!path) return -EFAULT;
    return vfs_chmod(path, mode);
}

static int64_t wrap_chmod(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_chmod((const char *)a1, (uint32_t)a2);
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, uint64_t offset) {
    process_t *proc = process_current();
    if (!proc) return (void *)-ESRCH;

    if (length == 0) return (void *)-EINVAL;
    if (length > 0x100000000UL) return (void *)-EINVAL;

    length = PAGE_ALIGN_UP(length);

    uint64_t start;
    if (flags & MAP_FIXED) {
        if (!addr || ((uint64_t)addr & (PAGE_SIZE - 1))) {
            return (void *)-EINVAL;
        }
        start = (uint64_t)addr;
    } else {
        start = USER_MMAP_START;
        mmap_region_t *region = proc->mmap_regions;
        while (region) {
            if (start + length <= region->start) {
                break;
            }
            start = PAGE_ALIGN_UP(region->end);
            region = region->next;
        }
        if (start + length >= USER_MMAP_END) {
            return (void *)-ENOMEM;
        }
    }

    file_t *file = NULL;
    if (!(flags & MAP_ANONYMOUS)) {
        if (fd < 0 || fd >= MAX_FDS || !proc->fds[fd].file) {
            return (void *)-EBADF;
        }
        file = proc->fds[fd].file;
    }

    uint64_t page_flags = PTE_USER;
    if (prot & PROT_WRITE) page_flags |= PTE_WRITABLE;

    for (uint64_t page = start; page < start + length; page += PAGE_SIZE) {
        void *phys = physmem_alloc_page();
        if (!phys) {
            for (uint64_t p = start; p < page; p += PAGE_SIZE) {
                uint64_t phys_addr = paging_get_phys(p);
                if (phys_addr) {
                    physmem_free_page((void *)phys_addr);
                }
            }
            return (void *)-ENOMEM;
        }
        memset(phys, 0, PAGE_SIZE);
        paging_map_page_in_space(proc->page_table, page, (uint64_t)phys, page_flags);
    }

    mmap_region_t *new_region = physmem_alloc_page();
    if (!new_region) {
        for (uint64_t page = start; page < start + length; page += PAGE_SIZE) {
            uint64_t phys = paging_get_phys(page);
            if (phys) {
                physmem_free_page((void *)phys);
            }
        }
        return (void *)-ENOMEM;
    }

    new_region->start = start;
    new_region->end = start + length;
    new_region->prot = prot;
    new_region->flags = flags;
    new_region->file = file;
    new_region->file_offset = offset;
    new_region->next = proc->mmap_regions;
    proc->mmap_regions = new_region;

    return (void *)start;
}

static int64_t wrap_mmap(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    return (int64_t)sys_mmap((void *)a1, (size_t)a2, (int)a3, (int)a4, (int)a5, 0);
}

int sys_munmap(void *addr, size_t length) {
    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (!addr || ((uint64_t)addr & (PAGE_SIZE - 1))) {
        return -EINVAL;
    }

    uint64_t start = (uint64_t)addr;
    uint64_t end = start + PAGE_ALIGN_UP(length);

    mmap_region_t **prev_ptr = &proc->mmap_regions;
    mmap_region_t *region = proc->mmap_regions;

    while (region) {
        if (region->start == start && region->end == end) {
            for (uint64_t page = region->start; page < region->end; page += PAGE_SIZE) {
                uint64_t phys = paging_get_phys(page);
                if (phys) {
                    physmem_free_page((void *)phys);
                    paging_unmap_page(page);
                }
            }

            *prev_ptr = region->next;
            physmem_free_page(region);
            return 0;
        }
        prev_ptr = &region->next;
        region = region->next;
    }

    return -EINVAL;
}

static int64_t wrap_munmap(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    return sys_munmap((void *)a1, (size_t)a2);
}

void syscall_init(void) {
    memset(syscall_table, 0, sizeof(syscall_table));

    syscall_table[SYS_EXIT] = wrap_exit;
    syscall_table[SYS_FORK] = wrap_fork;
    syscall_table[SYS_READ] = wrap_read;
    syscall_table[SYS_WRITE] = wrap_write;
    syscall_table[SYS_OPEN] = wrap_open;
    syscall_table[SYS_CLOSE] = wrap_close;
    syscall_table[SYS_EXECVE] = wrap_execve;
    syscall_table[SYS_GETPID] = wrap_getpid;
    syscall_table[SYS_GETPPID] = wrap_getppid;
    syscall_table[SYS_GETUID] = wrap_getuid;
    syscall_table[SYS_GETGID] = wrap_getgid;
    syscall_table[SYS_UNAME] = wrap_uname;
    syscall_table[SYS_BRK] = wrap_brk;
    syscall_table[SYS_WAITPID] = wrap_waitpid;
    syscall_table[SYS_PIPE] = wrap_pipe;
    syscall_table[SYS_DUP2] = wrap_dup2;
    syscall_table[SYS_READDIR] = wrap_readdir;
    syscall_table[SYS_CHMOD] = wrap_chmod;
    syscall_table[SYS_MMAP] = wrap_mmap;
    syscall_table[SYS_MUNMAP] = wrap_munmap;
}
