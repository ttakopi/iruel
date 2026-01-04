#include "include/kernel.h"
#include "include/memory.h"
#include "include/process.h"
#include "include/fs.h"
#include "include/errno.h"
#include "include/pipe.h"

typedef struct pipe {
    uint8_t *buf;
    size_t size;
    size_t read_pos;
    size_t write_pos;
    size_t count;
    int readers;
    int writers;
    process_t *read_waiters;
    process_t *write_waiters;
} pipe_t;

static void pipe_wake_readers(pipe_t *p) {
    while (p->read_waiters) {
        process_t *proc = p->read_waiters;
        p->read_waiters = proc->wait_next;
        proc->wait_next = NULL;
        proc->wait_type = WAIT_NONE;
        proc->wait_obj = NULL;
        proc->state = PROC_READY;
        schedule_make_ready(proc);
    }
}

static void pipe_wake_writers(pipe_t *p) {
    while (p->write_waiters) {
        process_t *proc = p->write_waiters;
        p->write_waiters = proc->wait_next;
        proc->wait_next = NULL;
        proc->wait_type = WAIT_NONE;
        proc->wait_obj = NULL;
        proc->state = PROC_READY;
        schedule_make_ready(proc);
    }
}

static int64_t pipe_read(file_t *f, void *buf, size_t count) {
    pipe_t *p = (pipe_t *)f->inode->data;
    if (!p || !buf) return -EIO;

    size_t read_total = 0;
    while (read_total < count) {
        if (p->count == 0) {
            if (p->writers == 0) {
                break;
            }
            process_t *proc = process_current();
            proc->state = PROC_BLOCKED;
            proc->wait_type = WAIT_PIPE_READ;
            proc->wait_obj = p;
            proc->wait_next = p->read_waiters;
            p->read_waiters = proc;
            schedule();
            continue;
        }

        size_t n = count - read_total;
        if (n > p->count) n = p->count;
        size_t first = p->size - p->read_pos;
        if (n > first) n = first;

        memcpy((uint8_t *)buf + read_total, p->buf + p->read_pos, n);
        p->read_pos = (p->read_pos + n) % p->size;
        p->count -= n;
        read_total += n;

        pipe_wake_writers(p);
    }

    return read_total;
}

static int64_t pipe_write(file_t *f, const void *buf, size_t count) {
    pipe_t *p = (pipe_t *)f->inode->data;
    if (!p || !buf) return -EIO;
    if (p->readers == 0) return -EPIPE;

    size_t written = 0;
    while (written < count) {
        if (p->count == p->size) {
            if (p->readers == 0) return -EPIPE;
            process_t *proc = process_current();
            proc->state = PROC_BLOCKED;
            proc->wait_type = WAIT_PIPE_WRITE;
            proc->wait_obj = p;
            proc->wait_next = p->write_waiters;
            p->write_waiters = proc;
            schedule();
            continue;
        }

        size_t space = p->size - p->count;
        size_t n = count - written;
        if (n > space) n = space;
        size_t first = p->size - p->write_pos;
        if (n > first) n = first;

        memcpy(p->buf + p->write_pos, (const uint8_t *)buf + written, n);
        p->write_pos = (p->write_pos + n) % p->size;
        p->count += n;
        written += n;

        pipe_wake_readers(p);
    }

    return written;
}

static int pipe_close(file_t *f) {
    pipe_t *p = (pipe_t *)f->inode->data;
    if (!p) return -EIO;

    if (f->flags & O_WRONLY) {
        if (p->writers > 0) p->writers--;
        if (p->writers == 0) {
            pipe_wake_readers(p);
        }
    } else {
        if (p->readers > 0) p->readers--;
        if (p->readers == 0) {
            pipe_wake_writers(p);
        }
    }

    if (p->readers == 0 && p->writers == 0) {
        if (p->buf) {
            physmem_free_page(p->buf);
        }
        physmem_free_page(f->inode);
        physmem_free_page(p);
    }

    return 0;
}

static const file_ops_t pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .open = NULL,
    .close = pipe_close,
    .lseek = NULL,
    .readdir = NULL,
};

int pipe_create(file_t **read_file, file_t **write_file) {
    if (!read_file || !write_file) return -EFAULT;

    pipe_t *p = physmem_alloc_page();
    if (!p) return -ENOMEM;
    memset(p, 0, sizeof(pipe_t));

    p->buf = physmem_alloc_page();
    if (!p->buf) {
        physmem_free_page(p);
        return -ENOMEM;
    }
    p->size = PAGE_SIZE;
    p->readers = 1;
    p->writers = 1;

    inode_t *inode = physmem_alloc_page();
    if (!inode) {
        physmem_free_page(p->buf);
        physmem_free_page(p);
        return -ENOMEM;
    }
    memset(inode, 0, sizeof(inode_t));
    inode->type = FT_CHARDEV;
    inode->f_ops = &pipe_ops;
    inode->data = p;

    file_t *rf = physmem_alloc_page();
    if (!rf) {
        physmem_free_page(inode);
        physmem_free_page(p->buf);
        physmem_free_page(p);
        return -ENOMEM;
    }
    memset(rf, 0, sizeof(file_t));
    rf->inode = inode;
    rf->flags = O_RDONLY;
    rf->refcount = 1;
    rf->ops = inode->f_ops;

    file_t *wf = physmem_alloc_page();
    if (!wf) {
        physmem_free_page(rf);
        physmem_free_page(inode);
        physmem_free_page(p->buf);
        physmem_free_page(p);
        return -ENOMEM;
    }
    memset(wf, 0, sizeof(file_t));
    wf->inode = inode;
    wf->flags = O_WRONLY;
    wf->refcount = 1;
    wf->ops = inode->f_ops;

    *read_file = rf;
    *write_file = wf;
    return 0;
}
