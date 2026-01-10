#ifndef _PROCESS_H
#define _PROCESS_H

#include <stdint.h>
#include <stddef.h>

#define MAX_PROCESSES   64
#define MAX_FDS         16

typedef enum {
    PROC_UNUSED = 0,
    PROC_CREATED,
    PROC_READY,
    PROC_RUNNING,
    PROC_BLOCKED,
    PROC_ZOMBIE
} proc_state_t;

typedef enum {
    WAIT_NONE = 0,
    WAIT_SLEEP,
    WAIT_PIPE_READ,
    WAIT_PIPE_WRITE,
    WAIT_CHILD
} wait_type_t;

typedef struct {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no, err_code;
    uint64_t rip, cs, rflags, rsp, ss;
} __attribute__((packed)) cpu_context_t;

struct file;
typedef struct {
    struct file *file;
    int flags;
} fd_entry_t;

typedef struct mmap_region {
    uint64_t start;
    uint64_t end;
    int prot;
    int flags;
    struct file *file;
    uint64_t file_offset;
    struct mmap_region *next;
} mmap_region_t;

typedef struct process {
    int pid;
    int ppid;
    int uid;
    int gid;
    proc_state_t state;

    uint64_t *page_table;
    uint64_t heap_start;
    uint64_t heap_end;
    uint64_t stack_top;

    cpu_context_t *context;
    uint64_t kernel_stack;

    fd_entry_t fds[MAX_FDS];

    int priority;
    uint64_t time_slice;

    struct process *rq_next;
    struct process *rq_prev;
    struct process *wait_next;
    int in_run_queue;
    wait_type_t wait_type;
    void *wait_obj;
    int wait_pid;
    uint64_t wake_tick;

    char name[32];
    
    struct mmap_region *mmap_regions;
} process_t;

void process_init(void);
process_t *process_create(const char *name);
int process_fork(void);
int process_exec(const char *path, char *const argv[], char *const envp[]);
void process_exit(int status) __attribute__((noreturn));
process_t *process_current(void);
void process_set_context(cpu_context_t *ctx);
process_t *process_get(int pid);
int process_getpid(void);
int process_getppid(void);
void process_sleep(uint64_t ticks);

void schedule_init(void);
void schedule(void);
void schedule_yield(void);
void schedule_tick(void);
void schedule_make_ready(process_t *proc);
uint64_t schedule_get_ticks(void);

extern void context_switch(cpu_context_t **old, cpu_context_t *new);
extern void switch_to(cpu_context_t *ctx) __attribute__((noreturn));

#endif
