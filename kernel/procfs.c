#include "include/kernel.h"
#include "include/memory.h"
#include "include/process.h"
#include "include/fs.h"
#include "include/errno.h"

extern process_t processes[];

static int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

typedef enum {
    PROCFS_ROOT = 0,
    PROCFS_UPTIME,
    PROCFS_PID_DIR,
    PROCFS_STATUS
} procfs_kind_t;

typedef struct {
    procfs_kind_t kind;
    int pid;
} procfs_node_t;

static procfs_node_t proc_root_node = { PROCFS_ROOT, 0 };

static int procfs_readdir(file_t *f, dirent_t *dent);
static inode_t *procfs_lookup(inode_t *dir, const char *name);

static const file_ops_t proc_dir_ops = {
    .read = NULL,
    .write = NULL,
    .open = NULL,
    .close = NULL,
    .lseek = NULL,
    .readdir = procfs_readdir,
};

static const inode_ops_t proc_dir_iops = {
    .lookup = procfs_lookup,
    .create = NULL,
    .mkdir = NULL,
    .unlink = NULL,
};

static size_t procfs_append(char *buf, size_t pos, const char *s, size_t max) {
    while (*s && pos < max) {
        buf[pos++] = *s++;
    }
    return pos;
}

static size_t procfs_append_uint(char *buf, size_t pos, uint64_t val, size_t max) {
    char tmp[32];
    size_t n = 0;
    if (val == 0) {
        tmp[n++] = '0';
    } else {
        while (val > 0 && n < sizeof(tmp)) {
            tmp[n++] = '0' + (val % 10);
            val /= 10;
        }
    }
    while (n > 0 && pos < max) {
        buf[pos++] = tmp[--n];
    }
    return pos;
}

static process_t *procfs_find_process(int pid) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        process_t *p = &processes[i];
        if (p->state != PROC_UNUSED && p->pid == pid) {
            return p;
        }
    }
    return NULL;
}

static int64_t procfs_file_read(file_t *f, void *buf, size_t count) {
    procfs_node_t *node = (procfs_node_t *)f->inode->data;
    if (!node || !buf) return -EIO;

    char tmp[256];
    size_t len = 0;

    if (node->kind == PROCFS_UPTIME) {
        uint64_t ticks = schedule_get_ticks();
        len = procfs_append(tmp, len, "ticks ", sizeof(tmp));
        len = procfs_append_uint(tmp, len, ticks, sizeof(tmp));
        len = procfs_append(tmp, len, "\n", sizeof(tmp));
    } else if (node->kind == PROCFS_STATUS) {
        process_t *p = procfs_find_process(node->pid);
        if (!p) return 0;
        len = procfs_append(tmp, len, "pid ", sizeof(tmp));
        len = procfs_append_uint(tmp, len, (uint64_t)p->pid, sizeof(tmp));
        len = procfs_append(tmp, len, "\nppid ", sizeof(tmp));
        len = procfs_append_uint(tmp, len, (uint64_t)p->ppid, sizeof(tmp));
        len = procfs_append(tmp, len, "\nuid ", sizeof(tmp));
        len = procfs_append_uint(tmp, len, (uint64_t)p->uid, sizeof(tmp));
        len = procfs_append(tmp, len, "\ngid ", sizeof(tmp));
        len = procfs_append_uint(tmp, len, (uint64_t)p->gid, sizeof(tmp));
        len = procfs_append(tmp, len, "\nstate ", sizeof(tmp));
        const char *state = "unknown";
        if (p->state == PROC_CREATED) state = "created";
        else if (p->state == PROC_READY) state = "ready";
        else if (p->state == PROC_RUNNING) state = "running";
        else if (p->state == PROC_BLOCKED) state = "blocked";
        else if (p->state == PROC_ZOMBIE) state = "zombie";
        len = procfs_append(tmp, len, state, sizeof(tmp));
        len = procfs_append(tmp, len, "\n", sizeof(tmp));
    }

    if (f->offset >= len) return 0;
    size_t remaining = len - f->offset;
    if (count > remaining) count = remaining;
    memcpy(buf, tmp + f->offset, count);
    f->offset += count;
    return count;
}

static const file_ops_t proc_file_ops = {
    .read = procfs_file_read,
    .write = NULL,
    .open = NULL,
    .close = NULL,
    .lseek = NULL,
    .readdir = NULL,
};

static inode_t *procfs_make_inode(procfs_kind_t kind, int pid, uint32_t type,
                                  const file_ops_t *fops, const inode_ops_t *iops) {
    inode_t *inode = physmem_alloc_page();
    if (!inode) return NULL;
    memset(inode, 0, sizeof(inode_t));

    procfs_node_t *node = physmem_alloc_page();
    if (!node) {
        physmem_free_page(inode);
        return NULL;
    }
    node->kind = kind;
    node->pid = pid;

    inode->type = type;
    inode->f_ops = fops;
    inode->i_ops = iops;
    inode->data = node;
    inode->mode = (type == FT_DIR) ? 0555 : 0444;

    return inode;
}

static int procfs_is_digits(const char *s) {
    if (!s || *s == '\0') return 0;
    while (*s) {
        if (*s < '0' || *s > '9') return 0;
        s++;
    }
    return 1;
}

static int procfs_atoi(const char *s) {
    int v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v;
}

static inode_t *procfs_lookup(inode_t *dir, const char *name) {
    procfs_node_t *node = (procfs_node_t *)dir->data;
    if (!node || !name) return NULL;

    if (node->kind == PROCFS_ROOT) {
        if (strcmp(name, "uptime") == 0) {
            return procfs_make_inode(PROCFS_UPTIME, 0, FT_FILE, &proc_file_ops, NULL);
        }
        if (procfs_is_digits(name)) {
            int pid = procfs_atoi(name);
            if (!procfs_find_process(pid)) return NULL;
            return procfs_make_inode(PROCFS_PID_DIR, pid, FT_DIR, &proc_dir_ops, &proc_dir_iops);
        }
        return NULL;
    }

    if (node->kind == PROCFS_PID_DIR) {
        if (strcmp(name, "status") == 0) {
            return procfs_make_inode(PROCFS_STATUS, node->pid, FT_FILE, &proc_file_ops, NULL);
        }
    }

    return NULL;
}

static int procfs_readdir(file_t *f, dirent_t *dent) {
    procfs_node_t *node = (procfs_node_t *)f->inode->data;
    if (!node || !dent) return -EIO;

    if (node->kind == PROCFS_ROOT) {
        int index = (int)f->offset;
        if (index == 0) {
            dent->ino = 1;
            dent->type = FT_FILE;
            strcpy(dent->name, "uptime");
            f->offset++;
            return 1;
        }
        int pid_index = 0;
        for (int i = 0; i < MAX_PROCESSES; i++) {
            process_t *p = &processes[i];
            if (p->state == PROC_UNUSED) continue;
            if (pid_index + 1 == index) {
                dent->ino = (uint32_t)p->pid;
                dent->type = FT_DIR;
                char tmp[16];
                size_t pos = 0;
                pos = procfs_append_uint(tmp, pos, (uint64_t)p->pid, sizeof(tmp));
                tmp[pos] = '\0';
                strcpy(dent->name, tmp);
                f->offset++;
                return 1;
            }
            pid_index++;
        }
        return 0;
    }

    if (node->kind == PROCFS_PID_DIR) {
        int index = (int)f->offset;
        if (index == 0) {
            dent->ino = (uint32_t)node->pid;
            dent->type = FT_FILE;
            strcpy(dent->name, "status");
            f->offset++;
            return 1;
        }
        return 0;
    }

    return 0;
}

void procfs_init(void) {
    inode_t *proc_dir = ramfs_create_dir("/proc");
    if (!proc_dir) {
        panic("Failed to create /proc");
    }

    proc_dir->type = FT_DIR;
    proc_dir->f_ops = &proc_dir_ops;
    proc_dir->i_ops = &proc_dir_iops;
    proc_dir->data = &proc_root_node;
}
