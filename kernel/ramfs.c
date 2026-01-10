#include "include/kernel.h"
#include "include/memory.h"
#include "include/fs.h"
#include "include/errno.h"

#define MAX_DIR_ENTRIES 64

typedef struct {
    char name[NAME_MAX];
    inode_t *inode;
} ramfs_dirent_t;

typedef struct {
    ramfs_dirent_t entries[MAX_DIR_ENTRIES];
    int count;
} ramfs_dir_t;

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} ramfs_file_t;

static char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

static int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static uint32_t next_ino = 1;

static inode_t *ramfs_lookup(inode_t *dir, const char *name);
static int ramfs_create(inode_t *dir, const char *name, int mode);

static int64_t ramfs_file_read(file_t *f, void *buf, size_t count) {
    ramfs_file_t *rf = (ramfs_file_t *)f->inode->data;
    if (!rf) return -EIO;

    if (f->offset >= rf->size) return 0;

    size_t to_read = count;
    if (f->offset + to_read > rf->size) {
        to_read = rf->size - f->offset;
    }

    memcpy(buf, rf->data + f->offset, to_read);
    f->offset += to_read;

    return to_read;
}

static int ramfs_file_open(file_t *f) {
    ramfs_file_t *rf = (ramfs_file_t *)f->inode->data;
    if (!rf) return -EIO;
    if (f->flags & O_TRUNC) {
        rf->size = 0;
        f->inode->size = 0;
        f->offset = 0;
    }
    if (f->flags & O_APPEND) {
        f->offset = rf->size;
    }
    return 0;
}

static int64_t ramfs_file_write(file_t *f, const void *buf, size_t count) {
    ramfs_file_t *rf = (ramfs_file_t *)f->inode->data;
    if (!rf) return -EIO;

    if (f->flags & O_APPEND) {
        f->offset = rf->size;
    }

    if (f->offset + count > rf->capacity) {
        size_t new_cap = (f->offset + count + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        size_t new_pages = new_cap / PAGE_SIZE;
        uint8_t *new_data = physmem_alloc_pages(new_pages);
        if (!new_data) return -ENOSPC;

        if (rf->data) {
            memcpy(new_data, rf->data, rf->size);
            if (rf->capacity) {
                physmem_free_pages(rf->data, rf->capacity / PAGE_SIZE);
            }
        }
        rf->data = new_data;
        rf->capacity = new_cap;
    }

    memcpy(rf->data + f->offset, buf, count);
    f->offset += count;

    if (f->offset > rf->size) {
        rf->size = f->offset;
        f->inode->size = rf->size;
    }

    return count;
}

static const file_ops_t ramfs_file_ops = {
    .read = ramfs_file_read,
    .write = ramfs_file_write,
    .open = ramfs_file_open,
    .close = NULL,
    .lseek = NULL,
    .readdir = NULL,
};

static int ramfs_dir_readdir(file_t *f, dirent_t *dent) {
    ramfs_dir_t *rd = (ramfs_dir_t *)f->inode->data;
    if (!rd) return -EIO;

    int index = f->offset;
    if (index >= rd->count) return 0;

    dent->ino = rd->entries[index].inode->ino;
    dent->type = rd->entries[index].inode->type;
    strcpy(dent->name, rd->entries[index].name);

    f->offset++;
    return 1;
}

static const file_ops_t ramfs_dir_ops = {
    .read = NULL,
    .write = NULL,
    .open = NULL,
    .close = NULL,
    .lseek = NULL,
    .readdir = ramfs_dir_readdir,
};

static inode_t *ramfs_lookup(inode_t *dir, const char *name) {
    if (dir->type != FT_DIR) return NULL;

    ramfs_dir_t *rd = (ramfs_dir_t *)dir->data;
    if (!rd) return NULL;

    for (int i = 0; i < rd->count; i++) {
        if (strcmp(rd->entries[i].name, name) == 0) {
            return rd->entries[i].inode;
        }
    }

    return NULL;
}

static int ramfs_add_entry(inode_t *dir, const char *name, inode_t *inode) {
    ramfs_dir_t *rd = (ramfs_dir_t *)dir->data;
    if (!rd) return -EIO;

    if (rd->count >= MAX_DIR_ENTRIES) return -ENOSPC;

    strcpy(rd->entries[rd->count].name, name);
    rd->entries[rd->count].inode = inode;
    rd->count++;

    return 0;
}

static int ramfs_create(inode_t *dir, const char *name, int mode) {
    inode_t *inode = physmem_alloc_page();
    if (!inode) return -ENOMEM;

    memset(inode, 0, sizeof(inode_t));
    inode->ino = next_ino++;
    inode->type = FT_FILE;
    inode->mode = S_IFREG | (mode & 0777);
    inode->uid = 0;
    inode->gid = 0;
    inode->f_ops = &ramfs_file_ops;

    ramfs_file_t *rf = (ramfs_file_t *)((uint8_t *)inode + sizeof(inode_t));
    memset(rf, 0, sizeof(ramfs_file_t));
    inode->data = rf;

    return ramfs_add_entry(dir, name, inode);
}

static int ramfs_mkdir(inode_t *dir, const char *name, int mode) {
    inode_t *inode = physmem_alloc_page();
    if (!inode) return -ENOMEM;

    memset(inode, 0, sizeof(inode_t));
    inode->ino = next_ino++;
    inode->type = FT_DIR;
    inode->mode = S_IFDIR | (mode & 0777);
    inode->uid = 0;
    inode->gid = 0;
    inode->f_ops = &ramfs_dir_ops;

    ramfs_dir_t *rd = (ramfs_dir_t *)((uint8_t *)inode + sizeof(inode_t));
    memset(rd, 0, sizeof(ramfs_dir_t));
    inode->data = rd;

    static const inode_ops_t dir_iops = {
        .lookup = ramfs_lookup,
        .create = ramfs_create,
        .mkdir = ramfs_mkdir,
        .unlink = NULL,
    };
    inode->i_ops = &dir_iops;

    return ramfs_add_entry(dir, name, inode);
}

static const inode_ops_t ramfs_inode_ops = {
    .lookup = ramfs_lookup,
    .create = ramfs_create,
    .mkdir = ramfs_mkdir,
    .unlink = NULL,
};

extern void vfs_set_root(inode_t *root);

static inode_t *ramfs_create_root(void) {
    inode_t *root = physmem_alloc_page();
    if (!root) return NULL;

    memset(root, 0, sizeof(inode_t));
    root->ino = next_ino++;
    root->type = FT_DIR;
    root->mode = S_IFDIR | 0755;
    root->uid = 0;
    root->gid = 0;
    root->f_ops = &ramfs_dir_ops;
    root->i_ops = &ramfs_inode_ops;

    ramfs_dir_t *rd = (ramfs_dir_t *)((uint8_t *)root + sizeof(inode_t));
    memset(rd, 0, sizeof(ramfs_dir_t));
    root->data = rd;

    return root;
}

static inode_t *ramfs_get_dir(inode_t *root, const char *path) {
    if (!path || path[0] != '/') return NULL;
    if (strcmp(path, "/") == 0) return root;

    inode_t *current = root;
    const char *p = path + 1;

    while (*p) {
        const char *start = p;
        while (*p && *p != '/') p++;

        size_t len = p - start;
        if (len == 0) {
            if (*p == '/') p++;
            continue;
        }

        char name[NAME_MAX];
        if (len >= NAME_MAX) len = NAME_MAX - 1;
        for (size_t i = 0; i < len; i++) {
            name[i] = start[i];
        }
        name[len] = '\0';

        inode_t *next = ramfs_lookup(current, name);
        if (!next) {

            ramfs_mkdir(current, name, 0755);
            next = ramfs_lookup(current, name);
            if (!next) return NULL;
        }

        current = next;
        if (*p == '/') p++;
    }

    return current;
}

inode_t *ramfs_create_file(const char *path, const void *data, size_t size) {

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
    if (*filename == '\0') return NULL;

    extern inode_t *vfs_lookup(const char *path);
    inode_t *root = vfs_lookup("/");
    inode_t *dir = ramfs_get_dir(root, dir_path);
    if (!dir) return NULL;

    inode_t *inode = physmem_alloc_page();
    if (!inode) return NULL;

    memset(inode, 0, sizeof(inode_t));
    inode->ino = next_ino++;
    inode->type = FT_FILE;
    inode->mode = 0644;
    inode->size = 0;
    inode->f_ops = &ramfs_file_ops;

    ramfs_file_t *rf = (ramfs_file_t *)((uint8_t *)inode + sizeof(inode_t));
    memset(rf, 0, sizeof(ramfs_file_t));

    if (size > 0 && data) {
        size_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        rf->data = physmem_alloc_pages(pages);
        if (rf->data) {
            memcpy(rf->data, data, size);
            rf->size = size;
            rf->capacity = pages * PAGE_SIZE;
            inode->size = size;
        }
    }
    inode->data = rf;

    ramfs_add_entry(dir, filename, inode);
    return inode;
}

inode_t *ramfs_create_dir(const char *path) {
    extern inode_t *vfs_lookup(const char *path);
    inode_t *root = vfs_lookup("/");
    return ramfs_get_dir(root, path);
}

void ramfs_init(void) {
    inode_t *root = ramfs_create_root();
    if (!root) {
        panic("Failed to create ramfs root");
    }

    vfs_set_root(root);

    ramfs_mkdir(root, "bin", 0755);
    ramfs_mkdir(root, "etc", 0755);
    ramfs_mkdir(root, "dev", 0755);

    kprintf("ramfs initialized\n");
}
