#ifndef _FS_H
#define _FS_H

#include <stdint.h>
#include <stddef.h>

#define FT_UNKNOWN  0
#define FT_FILE     1
#define FT_DIR      2
#define FT_CHARDEV  3
#define FT_BLOCKDEV 4

#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define O_APPEND    0x0400

#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

#define S_IFMT      0170000
#define S_IFREG     0100000
#define S_IFDIR     0040000
#define S_IFCHR     0020000
#define S_IFBLK     0060000

#define S_IRUSR     0000400
#define S_IWUSR     0000200
#define S_IXUSR     0000100
#define S_IRGRP     0000040
#define S_IWGRP     0000020
#define S_IXGRP     0000010
#define S_IROTH     0000004
#define S_IWOTH     0000002
#define S_IXOTH     0000001

#define S_IRWXU     (S_IRUSR|S_IWUSR|S_IXUSR)
#define S_IRWXG     (S_IRGRP|S_IWGRP|S_IXGRP)
#define S_IRWXO     (S_IROTH|S_IWOTH|S_IXOTH)

#define PATH_MAX    256
#define NAME_MAX    64

struct file;
struct inode;
struct dirent;

typedef struct {
    int64_t (*read)(struct file *f, void *buf, size_t count);
    int64_t (*write)(struct file *f, const void *buf, size_t count);
    int (*open)(struct file *f);
    int (*close)(struct file *f);
    int64_t (*lseek)(struct file *f, int64_t offset, int whence);
    int (*readdir)(struct file *f, struct dirent *dent);
} file_ops_t;

typedef struct {
    struct inode *(*lookup)(struct inode *dir, const char *name);
    int (*create)(struct inode *dir, const char *name, int mode);
    int (*mkdir)(struct inode *dir, const char *name, int mode);
    int (*unlink)(struct inode *dir, const char *name);
} inode_ops_t;

typedef struct inode {
    uint32_t ino;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    void *data;
    const file_ops_t *f_ops;
    const inode_ops_t *i_ops;
} inode_t;

typedef struct file {
    inode_t *inode;
    uint64_t offset;
    int flags;
    int refcount;
    const file_ops_t *ops;
} file_t;

typedef struct dirent {
    uint32_t ino;
    uint32_t type;
    char name[NAME_MAX];
} dirent_t;

void vfs_init(void);
file_t *vfs_open(const char *path, int flags);
int vfs_close(file_t *f);
int64_t vfs_read(file_t *f, void *buf, size_t count);
int64_t vfs_write(file_t *f, const void *buf, size_t count);
int64_t vfs_lseek(file_t *f, int64_t offset, int whence);
int vfs_readdir(file_t *f, dirent_t *dent);
inode_t *vfs_lookup(const char *path);

void ramfs_init(void);
inode_t *ramfs_create_file(const char *path, const void *data, size_t size);
inode_t *ramfs_create_dir(const char *path);
int vfs_check_permission(inode_t *inode, int mask);
int vfs_chmod(const char *path, uint32_t mode);

void console_init(void);

#endif
