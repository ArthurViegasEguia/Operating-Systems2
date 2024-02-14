#include <kernel/proc.h>
#include <kernel/thread.h>
#include <kernel/console.h>
#include <kernel/kmalloc.h>
#include <kernel/fs.h>
#include <kernel/pipe.h>
#include <lib/syscall-num.h>
#include <lib/errcode.h>
#include <lib/stddef.h>
#include <lib/string.h>
#include <arch/asm.h>
// syscall handlers
static sysret_t sys_fork(void* arg);
static sysret_t sys_spawn(void* arg);
static sysret_t sys_wait(void* arg);
static sysret_t sys_exit(void* arg);
static sysret_t sys_getpid(void* arg);
static sysret_t sys_sleep(void* arg);
static sysret_t sys_open(void* arg);
static sysret_t sys_close(void* arg);
static sysret_t sys_read(void* arg);
static sysret_t sys_write(void* arg);
static sysret_t sys_link(void* arg);
static sysret_t sys_unlink(void* arg);
static sysret_t sys_mkdir(void* arg);
static sysret_t sys_chdir(void* arg);
static sysret_t sys_readdir(void* arg);
static sysret_t sys_rmdir(void* arg);
static sysret_t sys_fstat(void* arg);
static sysret_t sys_sbrk(void* arg);
static sysret_t sys_meminfo(void* arg);
static sysret_t sys_dup(void* arg);
static sysret_t sys_pipe(void* arg);
static sysret_t sys_info(void* arg);
static sysret_t sys_halt(void* arg);

extern size_t user_pgfault;
struct sys_info {
    size_t num_pgfault;
};

/*
 * Machine dependent syscall implementation: fetches the nth syscall argument.
 */
extern bool fetch_arg(void *arg, int n, sysarg_t *ret);

/*
 * Validate string passed by user.
 */
static bool validate_str(char *s);
/*
 * Validate buffer passed by user.
 */
static bool validate_ptr(void* ptr, size_t size);

static sysret_t (*syscalls[])(void*) = {
    [SYS_fork] = sys_fork,
    [SYS_spawn] = sys_spawn,
    [SYS_wait] = sys_wait,
    [SYS_exit] = sys_exit,
    [SYS_getpid] = sys_getpid,
    [SYS_sleep] = sys_sleep,
    [SYS_open] = sys_open,
    [SYS_close] = sys_close,
    [SYS_read] = sys_read,
    [SYS_write] = sys_write,
    [SYS_link] = sys_link,
    [SYS_unlink] = sys_unlink,
    [SYS_mkdir] = sys_mkdir,
    [SYS_chdir] = sys_chdir,
    [SYS_readdir] = sys_readdir,
    [SYS_rmdir] = sys_rmdir,
    [SYS_fstat] = sys_fstat,
    [SYS_sbrk] = sys_sbrk,
    [SYS_meminfo] = sys_meminfo,
    [SYS_dup] = sys_dup,
    [SYS_pipe] = sys_pipe,
    [SYS_info] = sys_info,
    [SYS_halt] = sys_halt,
};

static bool
validate_str(char *s)
{
    struct memregion *mr;
    // find given string's memory region
    if((mr = as_find_memregion(&proc_current()->as, (vaddr_t) s, 1)) == NULL) {
        return False;
    }
    // check in case the string keeps growing past user specified amount
    for(; s < (char*) mr->end; s++){
        if(*s == 0) {
            return True;
        }
    }
    return False;
}

static bool
validate_ptr(void* ptr, size_t size)
{
    vaddr_t ptraddr = (vaddr_t) ptr;
    if (ptraddr + size < ptraddr) {
        return False;
    }
    // verify argument ptr points to a valid chunk of memory of size bytes
    return as_find_memregion(&proc_current()->as, ptraddr, size) != NULL;
}

//Given a pointer to a file, looks through the process’s
//open file table to find an available file descriptor,
//and stores the pointer there. Returns the
//chosen file descriptor or ERR_NOMEM if none available
static int alloc_fd(struct file *f){
    struct proc *p = proc_current();
    int i;
    //Finds first available spot in the file descriptor table and allocates file
    for(i = 2; i < PROC_MAX_FILE; i++){
        if(p->fdTable[i] == NULL){
            p->fdTable[i] = f;
            return i;
        }
    }
    return ERR_NOMEM;
}


//Given a file descriptor, checks that it is valid 
//(i.e., that it is in the open file table for the current process)
//Returns true if valid and false otherwise
static bool validate_fd(int fd){
     struct proc *p = proc_current();
     if(fd >= 0 && fd < PROC_MAX_FILE && p->fdTable[fd] != NULL){
        return True;
     }
     return False;
}
//Forks the current process, returning ERR_NOMEM if not possible
//and the pid of child process if successful
// int fork(void);
static sysret_t
sys_fork(void *arg)
{   
    struct proc *p;
    if ((p = proc_fork()) == NULL) {
        return ERR_NOMEM;
    }
    return p->pid;
}

// int spawn(const char *args);
static sysret_t
sys_spawn(void *arg)
{
    int argc = 0;
    sysarg_t args;
    size_t len;
    char *token, *buf, **argv;
    struct proc *p;
    err_t err;

    // argument fetching and validating
    kassert(fetch_arg(arg, 1, &args));
    if (!validate_str((char*)args)) {
        return ERR_FAULT;
    }

    len = strlen((char*)args) + 1;
    if ((buf = kmalloc(len)) == NULL) {
        return ERR_NOMEM;
    }
    // make a copy of the string to not modify user data
    memcpy(buf, (void*)args, len);
    // figure out max number of arguments possible
    len = len / 2 < PROC_MAX_ARG ? len/2 : PROC_MAX_ARG;
    if ((argv = kmalloc((len+1)*sizeof(char*))) == NULL) {
        kfree(buf);
        return ERR_NOMEM;
    }
    // parse arguments  
    while ((token = strtok_r(NULL, " ", &buf)) != NULL) {
        argv[argc] = token;
        argc++;
    }
    argv[argc] = NULL;

    if ((err = proc_spawn(argv[0], argv, &p)) != ERR_OK) {
        return err;
    }
    return p->pid;
}

//Suspends the execution of the current process until its child
//process with pid pid returns. Puts the exit status of the child on
//wstatus
//Returns the pid of the child on success
//Returns ERR_CHILD if he caller does not have a child with the specified pid.
//Returns ERR_FAULT if address of wstatus is invalid.
// int wait(int pid, int *wstatus);
static sysret_t
sys_wait(void* arg)
{
    //Receives and processes the arguments
    sysarg_t pid_arg, pid_return;

    //kassert. If true no-op, else panic
    kassert(fetch_arg(arg, 1, &pid_arg));
    kassert(fetch_arg(arg, 2, &pid_return));

    //Validates pointer
    if(pid_return != NULL && !validate_ptr((void *)pid_return, sizeof(int))){
        return ERR_FAULT;
    }

    //Waits for process, returning pid on success
    return proc_wait((int) pid_arg, (int *) pid_return);
    
}

//Exits process with return value status.
//Returns this status to the parent, if possible
//does not return on success
//Return ERR_FAULT if it fails

// void exit(int status);
static sysret_t
sys_exit(void* arg)
{ 
    sysarg_t status;

    //Fetch arguments from void* arg
    kassert(fetch_arg(arg, 1, &status));

    //Parsing arguments and exiting process
    int status_arg = (int) status;
    proc_exit(status_arg);

    //THis line should not be reached
    return ERR_FAULT;
    
}

// int getpid(void);
static sysret_t
sys_getpid(void* arg)
{
    return proc_current()->pid;
}

// void sleep(unsigned int, seconds);
static sysret_t
sys_sleep(void* arg)
{
    panic("syscall sleep not implemented");
}

// int open(const char *pathname, int flags, fmode_t mode);
//Opens textfile at pathname, with flags_arg flags, and with mode_arg mode
static sysret_t
sys_open(void *arg)
{
    //pattern match with existing system call
    //Fetch the arguments from void *arg
    sysarg_t pathname_arg, flags_arg, mode_arg;
    //kassert. If true no-op, else panic
    kassert(fetch_arg(arg, 1, &pathname_arg));
    kassert(fetch_arg(arg, 2, &flags_arg));
    kassert(fetch_arg(arg, 3, &mode_arg));

    //Convert arguments to a certain type
    char *pathname = (char *)pathname_arg;
    int flags = (int)flags_arg;
    fmode_t mode = (fmode_t)mode_arg;

    //Validate the address of the pathname
    if(!validate_str((char *)pathname)){
        return ERR_FAULT;
    }

    //Initiates process
    struct proc *p = proc_current();
    kassert(p);

    //Finds the first available index in the file descryptor table
    //Returns ERR_NOMEM if not possible to validate it
    struct file *file = kmalloc(sizeof(struct file));
    int ind;
    ind = alloc_fd(file);
    if(ind == ERR_NOMEM){
        return ERR_NOMEM;
    }

    //Open file, this handles a variety of errors
    err_t res = fs_open_file(pathname, flags, mode, &(p->fdTable[ind]));
    if(res != ERR_OK){
        return res;
    }

    //Returns file descriptor
    return (sysret_t)ind;
}

// int close(int fd);
//Closes and removes open file at position fd from the file descriptor table
//returns ERR_OK if successful and ERR_INVAL otherwise
static sysret_t sys_close(void *arg) {
    //Fetch the arguments from void *arg
    sysarg_t fd;
    kassert(fetch_arg(arg, 1, &fd));

    struct proc *p = proc_current();

    //Decrements the file reference count if there are multiple pointers to
    //the same file or close it otherwise
    if(validate_fd(fd)) {
        fs_close_file(p->fdTable[fd]);
        p->fdTable[fd] = NULL;
        return ERR_OK;
    }
    return ERR_INVAL;
}

// int read(int fd, void *buf, size_t count);
//Reads count bytes from file at fd position at the file descriptor table 
//Stores read bytes in buf
//Returns the number of bytes read if successful
//ERR_FAULT if the address of the buffer is invalid
//ERR_INVAL if fd is not a valid open file descriptor
static sysret_t
sys_read(void* arg)
{

    //Fetch arguments from void* arg and parses data
    sysarg_t fd, buf, count;

    kassert(fetch_arg(arg, 1, &fd));
    kassert(fetch_arg(arg, 2, &buf));
    kassert(fetch_arg(arg, 3, &count));

    //Validates pointer buf
    struct proc *p = proc_current();
    if (!validate_ptr((void*)buf, (size_t)count)) {
        return ERR_FAULT;
    }

    //Reads from stdin input (console) or file, depending on the file descriptor
    if (p->fdTable[fd] == &stdin) { 
        return console_read((void*)buf, (size_t)count);
    } else if (validate_fd(fd) && count > 0) {
        return fs_read_file(p->fdTable[fd], (void*)buf, (size_t)count, &p->fdTable[fd]->f_pos);
    }

    return ERR_INVAL;
}

// int write(int fd, const void *buf, size_t count)
//Writes count bytes from buf into file 
//File is of position fd in file descriptor table
//Returns the number of bytes written
//On railure return ERR_FAULT if addess of buff is invalid
//ERR_INVAL if fd isn't a valid file descriptor
//and ERR_END if fd refers to a pipe with no open read
static sysret_t
sys_write(void* arg)
{
    sysarg_t fd, count, buf;
    //Fetch arguments from void* arg
    kassert(fetch_arg(arg, 1, &fd));
    kassert(fetch_arg(arg, 3, &count));
    kassert(fetch_arg(arg, 2, &buf));

    struct proc *p = proc_current();
    
    //Validates buffer pointer
    if (!validate_ptr((void*)buf, (size_t)count)) {
        return ERR_FAULT;
    }

    //Writes to stdout (console) or file, depending on the value of fd
    if (p->fdTable[fd] == &stdout) {
        return console_write((void*)buf, (size_t) count);
    } else if (validate_fd(fd)) {
        return fs_write_file(p->fdTable[fd], (void*)buf, (size_t) count, &p->fdTable[fd]->f_pos);
    }

    return ERR_INVAL;
}

// int link(const char *oldpath, const char *newpath)
static sysret_t
sys_link(void *arg)
{
    sysarg_t oldpath, newpath;

    kassert(fetch_arg(arg, 1, &oldpath));
    kassert(fetch_arg(arg, 2, &newpath));

    if (!validate_str((char*)oldpath) || !validate_str((char*)newpath)) {
        return ERR_FAULT;
    }

    return fs_link((char*)oldpath, (char*)newpath);
}

// int unlink(const char *pathname)
static sysret_t
sys_unlink(void *arg)
{
    sysarg_t pathname;

    kassert(fetch_arg(arg, 1, &pathname));

    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    return fs_unlink((char*)pathname);
}

// int mkdir(const char *pathname)
static sysret_t
sys_mkdir(void *arg)
{
    sysarg_t pathname;

    kassert(fetch_arg(arg, 1, &pathname));

    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    return fs_mkdir((char*)pathname);
}

// int chdir(const char *path)
static sysret_t
sys_chdir(void *arg)
{
    sysarg_t path;
    struct inode *inode;
    struct proc *p;
    err_t err;

    kassert(fetch_arg(arg, 1, &path));

    if (!validate_str((char*)path)) {
        return ERR_FAULT;
    }

    if ((err = fs_find_inode((char*)path, &inode)) != ERR_OK) {
        return err;
    }

    p = proc_current();
    kassert(p);
    kassert(p->cwd);
    fs_release_inode(p->cwd);
    p->cwd = inode;
    return ERR_OK;
}


//int readdir(int fd, struct dirent *dirent);
//Populate the struct dirent pointer with the next entry in a directory.
//Returns ERR_OK on success
//ERR_FAULT if the addess of dirent is invalid
//ERR_INVAL if fd isn't a valid open file descriptor
//ERR_FTYPE if fd does not point to a directory
//ERR_NOMEM if failed to allocate memory
//ERR_END - End of the directory is reached
static sysret_t
sys_readdir(void *arg)
{
    sysarg_t fd, dirent;

    //Fetch arguments from void* arg
    kassert(fetch_arg(arg, 1, &fd));
    kassert(fetch_arg(arg, 2, &dirent));

    struct dirent *dirent_arg = (struct dirent *) dirent;
    struct proc *p = proc_current();

    //Pointer dirent validation
    if (!validate_ptr((void*)dirent, sizeof(struct dirent))) {
        return ERR_FAULT;
    }

    //Pointer dirent validation
    if(!validate_fd(fd)){
        return ERR_INVAL;
    }

    //Tries to perform the operation, returns error if found. Otherwise returns ERR_OK
    err_t res = fs_readdir(p->fdTable[fd], dirent_arg);
    if(res != ERR_OK){
        return res;
    }

    return ERR_OK;
}

// int rmdir(const char *pathname);
static sysret_t
sys_rmdir(void *arg)
{
    sysarg_t pathname;

    kassert(fetch_arg(arg, 1, &pathname));

    if (!validate_str((char*)pathname)) {
        return ERR_FAULT;
    }

    return fs_rmdir((char*)pathname);
}

// int fstat(int fd, struct stat *stat);
// Get the file status in the struct stat pointer passed in to the function.
// Returns ERR_OK on success
// ERR_FAULT if address of stat is invalid 
// and ERR_INVAL if fd isn't a valid file descriptor
static sysret_t
sys_fstat(void *arg)
{
    sysarg_t fd, stat;

    //Fetch arguments from void* arg
    kassert(fetch_arg(arg, 1, &fd));
    kassert(fetch_arg(arg, 2, &stat));

    struct stat *stat_arg = (struct stat *) stat;
    struct proc *p = proc_current();

    //Validates file descriptor
    if(!validate_fd(fd) || p->fdTable[fd] == &stdin || p->fdTable[fd] == &stdout){
        return ERR_INVAL;
    } 
    
    //Validates stat_arg pointer
    if(!validate_ptr((void*)stat_arg, sizeof(struct stat))){
        return ERR_FAULT;
    }

    //Populates stat struct
    stat_arg->inode_num = p->fdTable[fd]->f_inode->i_inum;
    stat_arg->ftype = p->fdTable[fd]->f_inode->i_ftype;
    stat_arg->size = p->fdTable[fd]->f_inode->i_size;

    return ERR_OK;

}

// void *sbrk(size_t increment);
static sysret_t
sys_sbrk(void *arg)
{
    panic("syscall sbrk not implemented");
}

// void memifo();
static sysret_t
sys_meminfo(void *arg)
{
    as_meminfo(&proc_current()->as);
    return ERR_OK;
}

// int dup(int fd);
//Duplicate the file descriptor fd. Reading/writing from a dupped fd advances
//the file position of the original fd
//Returns new file descriptor on success
//ERR_INVAL if the fd is not a valid file descriptor
//and ERR_NOMEM if no new file descriptors are available
static sysret_t
sys_dup(void *arg)
{
    sysarg_t fd;

    //Fetch arguments from void* arg
    kassert(fetch_arg(arg, 1, &fd));

    //Validates file descriptor
    if(!validate_fd(fd)){
        return ERR_INVAL;
    }

    //Finds available space, and makes it point to file descriptor fd
    struct proc *p = proc_current();
    for(int i = 1; i < PROC_MAX_FILE; i++){
        if(p->fdTable[i] == NULL){
            p->fdTable[i] = (p->fdTable[fd]);
            p->fdTable[fd]->f_ref++;
            return i;
        }
    }
    
    return ERR_NOMEM;

}

//Creates a pipe and two open file descriptors. The first
//one will be in the file descriptor table 
//in positon fds[0] and will be used to read from the pipe and the
//second will be in the file descriptor table in position
//fds[1] and be used to write to the pipe
//Returns ERR_OK on success
//ERR_FAULT if fds address is not valid
//ERR_NOMEM if 2 new file descriptors are not available
// int pipe(int* fds);
static sysret_t
sys_pipe(void* arg)
{
    sysarg_t fds;
    
    //Fetch arguments from void*
    kassert(fetch_arg(arg, 1, &fds));

    //Validates fds
    if(!validate_ptr((void *) fds, sizeof(int* [2]))){
        return ERR_FAULT;
    }
    
    //Returns ERR_OK on success, and ERR_NOMEM otherwise
    if(pipe_alloc((int *)fds) != NULL){
        return ERR_OK;
    }

    return ERR_NOMEM;
}

// void sys_info(struct sys_info *info);
static sysret_t
sys_info(void* arg)
{
    sysarg_t info;

    kassert(fetch_arg(arg, 1, &info));

    if (!validate_ptr((void*)info, sizeof(struct sys_info))) {
        return ERR_FAULT;
    }
    // fill in using user_pgfault 
    ((struct sys_info*)info)->num_pgfault = user_pgfault;
    return ERR_OK;
}

// void halt();
static sysret_t 
sys_halt(void* arg)
{
    shutdown();
    panic("shutdown failed");
}


sysret_t
syscall(int num, void *arg)
{
    kassert(proc_current());
    if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
        return syscalls[num](arg);
    } else {
        panic("Unknown system call");
    }
}


