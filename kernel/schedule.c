#include "include/kernel.h"
#include "include/memory.h"
#include "include/process.h"

extern process_t *process_current(void);

extern process_t processes[];

static volatile uint64_t ticks = 0;
static uint64_t time_slice_ticks = 10;
static process_t *run_head = NULL;
static process_t *run_tail = NULL;

extern void gdt_set_kernel_stack(uint64_t stack);
extern void switch_to(cpu_context_t *ctx);
void schedule_make_ready(process_t *proc);

void schedule_init(void) {
    ticks = 0;
    run_head = NULL;
    run_tail = NULL;
}

void schedule_tick(void) {
    ticks++;

    for (int i = 0; i < MAX_PROCESSES; i++) {
        process_t *p = &processes[i];
        if (p->state == PROC_BLOCKED && p->wait_type == WAIT_SLEEP &&
            p->wake_tick && ticks >= p->wake_tick) {
            p->wait_type = WAIT_NONE;
            p->wake_tick = 0;
            p->state = PROC_READY;
            schedule_make_ready(p);
        }
    }

    if (!irq_from_user()) {
        return;
    }

    process_t *proc = process_current();
    if (proc && proc->state == PROC_RUNNING) {
        proc->time_slice++;
        if (proc->time_slice >= time_slice_ticks) {
            proc->time_slice = 0;
            schedule_yield();
        }
    }
}

static process_t *find_next_process(void) {
    process_t *proc = run_head;
    if (!proc) {
        return NULL;
    }
    run_head = proc->rq_next;
    if (run_head) {
        run_head->rq_prev = NULL;
    } else {
        run_tail = NULL;
    }
    proc->rq_next = NULL;
    proc->rq_prev = NULL;
    proc->in_run_queue = 0;
    return proc;
}

void schedule(void) {
    cli();

    process_t *prev = process_current();
    process_t *next = find_next_process();

    if (prev && prev->state == PROC_RUNNING) {
        prev->state = PROC_READY;
        schedule_make_ready(prev);
    }

    if (!next) {
        sti();
        hlt();
        return;
    }

    if (prev == next) {
        next->state = PROC_RUNNING;
        sti();
        return;
    }

    next->state = PROC_RUNNING;

    extern process_t *current_process;
    current_process = next;

    kprintf("switch to pid %d (rip=%p rsp=%p rax=%ld rbx=%ld)\n",
            next->pid, next->context->rip, next->context->rsp,
            next->context->rax, next->context->rbx);

    paging_switch_address_space(next->page_table);

    gdt_set_kernel_stack(next->kernel_stack);

    switch_to(next->context);
}

void schedule_yield(void) {
    process_t *proc = process_current();
    if (proc) {
        proc->time_slice = 0;
    }
    schedule();
}

uint64_t schedule_get_ticks(void) {
    return ticks;
}

void schedule_make_ready(process_t *proc) {
    if (!proc) return;
    if (proc->in_run_queue) return;
    proc->rq_next = NULL;
    proc->rq_prev = run_tail;
    if (run_tail) {
        run_tail->rq_next = proc;
    } else {
        run_head = proc;
    }
    run_tail = proc;
    proc->in_run_queue = 1;
}
