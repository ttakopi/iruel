#include "include/kernel.h"
#include "include/memory.h"
#include "include/fs.h"
#include "include/errno.h"
#include "include/process.h"

static inode_t *root_inode = NULL;

static int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

inode_t *vfs_lookup(const char *path) {
    if (!path || path[0] != '/') {
        return NULL;
    }

    if (strcmp(path, "/") == 0) {
        return root_inode;
    }

    inode_t *current = root_inode;
    const char *p = path + 1;

    while (*p && current) {

        const char *start = p;
        while (*p && *p != '/') p++;

        size_t len = p - start;
        if (len == 0) {
            if (*p == '/') p++;
            continue;
        }

        if (current->type != FT_DIR || !current->i_ops || !current->i_ops->lookup) {
            return NULL;
        }

        char name[NAME_MAX];
        if (len >= NAME_MAX) len = NAME_MAX - 1;
        for (size_t i = 0; i < len; i++) {
            name[i] = start[i];
        }
        name[len] = '\0';

        current = current->i_ops->lookup(current, name);

        if (*p == '/') p++;
    }

    return current;
}

file_t *vfs_open(const char *path, int flags) {
    inode_t *inode = vfs_lookup(path);
    if (!inode) {
        if (flags & O_CREAT) {
            const char *last_slash = path;
            for (const char *p = path; *p; p++) {
                if (*p == '/') last_slash = p;
            }
            char dir_path[PATH_MAX];
            size_t dir_len = last_slash - path;
            if (dir_len == 0) dir_len = 1;
            for (size_t i = 0; i < dir_len && i < PATH_MAX - 1; i++) {
                dir_path[i] = path[i];
            }
            dir_path[dir_len] = '\0';
            const char *filename = last_slash + 1;
            if (*filename == '\0') {
                return NULL;
            }
            inode_t *dir = vfs_lookup(dir_path);
            if (!dir || dir->type != FT_DIR || !dir->i_ops || !dir->i_ops->create) {
                return NULL;
            }
            int perm_err = vfs_check_permission(dir, 2 | 1);
            if (perm_err < 0) {
                return NULL;
            }
            if (dir->i_ops->create(dir, filename, 0644) < 0) {
                return NULL;
            }
            inode = vfs_lookup(path);
        }
        if (!inode) {
            return NULL;
        }
    }

    int access_mode = flags & O_RDWR;
    int perm_mask = 0;
    if (access_mode == O_RDONLY || access_mode == O_RDWR) perm_mask |= 4;
    if (access_mode == O_WRONLY || access_mode == O_RDWR) perm_mask |= 2;
    
    int perm_err = vfs_check_permission(inode, perm_mask);
    if (perm_err < 0) {
        return NULL;
    }

    file_t *file = physmem_alloc_page();
    if (!file) {
        return NULL;
    }

    memset(file, 0, sizeof(file_t));
    file->inode = inode;
    file->offset = 0;
    file->flags = flags;
    file->refcount = 1;
    file->ops = inode->f_ops;

    if (file->ops && file->ops->open) {
        int ret = file->ops->open(file);
        if (ret < 0) {
            physmem_free_page(file);
            return NULL;
        }
    }

    return file;
}

int vfs_close(file_t *f) {
    if (!f) return -EBADF;

    f->refcount--;
    if (f->refcount <= 0) {
        if (f->ops && f->ops->close) {
            f->ops->close(f);
        }
        physmem_free_page(f);
    }

    return 0;
}

int64_t vfs_read(file_t *f, void *buf, size_t count) {
    if (!f || !buf) return -EFAULT;
    if (!f->ops || !f->ops->read) return -ENOSYS;
    
    int perm_err = vfs_check_permission(f->inode, 4);
    if (perm_err < 0) return perm_err;
    
    return f->ops->read(f, buf, count);
}

int64_t vfs_write(file_t *f, const void *buf, size_t count) {
    if (!f || !buf) return -EFAULT;
    if (!f->ops || !f->ops->write) return -ENOSYS;
    
    int perm_err = vfs_check_permission(f->inode, 2);
    if (perm_err < 0) return perm_err;
    
    return f->ops->write(f, buf, count);
}

int64_t vfs_lseek(file_t *f, int64_t offset, int whence) {
    if (!f) return -EBADF;

    if (f->ops && f->ops->lseek) {
        return f->ops->lseek(f, offset, whence);
    }

    int64_t new_offset;
    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = f->offset + offset;
            break;
        case SEEK_END:
            new_offset = f->inode->size + offset;
            break;
        default:
            return -EINVAL;
    }

    if (new_offset < 0) return -EINVAL;
    f->offset = new_offset;
    return new_offset;
}

int vfs_readdir(file_t *f, dirent_t *dent) {
    if (!f || !dent) return -EFAULT;
    if (!f->ops || !f->ops->readdir) return -ENOSYS;
    return f->ops->readdir(f, dent);
}

void vfs_set_root(inode_t *root) {
    root_inode = root;
}

void vfs_init(void) {
    root_inode = NULL;
}

int vfs_check_permission(inode_t *inode, int mask) {
    if (!inode) return -ENOENT;

    process_t *proc = process_current();
    if (!proc) return 0;

    if (proc->uid == 0) {
        return 0;
    }

    uint32_t mode = inode->mode;
    int check_bits = 0;

    if ((uint32_t)proc->uid == inode->uid) {
        check_bits = (mode >> 6) & 7;
    } else if ((uint32_t)proc->gid == inode->gid) {
        check_bits = (mode >> 3) & 7;
    } else {
        check_bits = mode & 7;
    }

    if ((mask & 4) && !(check_bits & 4)) return -EACCES;
    if ((mask & 2) && !(check_bits & 2)) return -EACCES;
    if ((mask & 1) && !(check_bits & 1)) return -EACCES;

    return 0;
}

int vfs_chmod(const char *path, uint32_t mode) {
    inode_t *inode = vfs_lookup(path);
    if (!inode) return -ENOENT;

    process_t *proc = process_current();
    if (!proc) return -ESRCH;

    if (proc->uid != 0 && (uint32_t)proc->uid != inode->uid) {
        return -EPERM;
    }

    inode->mode = (inode->mode & S_IFMT) | (mode & 0777);
    return 0;
}
