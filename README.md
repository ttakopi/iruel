# iruel

iruel is a small x86_64 toy kernel with a userspace, ramfs root filesystem, and a shell. it boots directly in qemu from the kernel image and runs userspace ELF binaries embedded into the kernel as an initramfs

### build
```
make -j4
```

### run
```
make run
```

the serial console is used for input and output. after boot, the shell runs on the same console

### shell
built-ins:
- help
- uname -a
- id
- exit

features:
- built-in tools and external commands in `/bin`
 - no pipes or redirection

### user tools
- ls
- cat
- echo
- pwd

### process model
- fork, execve, waitpid for userspace
- round robin scheduling with a run queue
- sleep/wakeup for blocking operations

### filesystem
- in memory ramfs with standard directories created at boot: `/bin`, `/etc`, `/dev`
- userspace binaries are embedded into the kernel at build time and exposed under `/bin`
- procfs mounted at `/proc` with `uptime` and per-pid `status`
