#include <kernel/console.h>
#include <kernel/proc.h>
#include <kernel/kmalloc.h>
#include <kernel/thread.h>
#include <kernel/list.h>
#include <kernel/fs.h>
#include <kernel/vpmap.h>
#include <arch/elf.h>
#include <arch/trap.h>
#include <arch/mmu.h>
#include <lib/errcode.h>
#include <lib/stddef.h>
#include <lib/string.h>

List ptable; // process table
struct spinlock ptable_lock;
struct spinlock pid_lock;
struct spinlock proc_lock;
static int pid_allocator;
struct kmem_cache *proc_allocator;


/* go through process table */
static void ptable_dump(void);
/* helper function for loading process's binary into its address space */ 
static err_t proc_load(struct proc *p, char *path, vaddr_t *entry_point);
/* helper function to set up the stack */
static err_t stack_setup(struct proc *p, char **argv, vaddr_t* ret_stackptr);
/* tranlsates a kernel vaddr to a user stack address, assumes stack is a single page */
#define USTACK_ADDR(addr) (pg_ofs(addr) + USTACK_UPPERBOUND - pg_size);

static struct proc*
proc_alloc()
{
    struct proc* p = (struct proc*) kmem_cache_alloc(proc_allocator);
    if (p != NULL) {
        spinlock_acquire(&pid_lock);\
        p->pid = pid_allocator++;
        spinlock_release(&pid_lock);
    }
    return p;
}

#pragma GCC diagnostic ignored "-Wunused-function"
static void
ptable_dump(void)
{
    kprintf("ptable dump:\n");
    spinlock_acquire(&ptable_lock);
    for (Node *n = list_begin(&ptable); n != list_end(&ptable); n = list_next(n)) {
        struct proc *p = list_entry(n, struct proc, proc_node);
        kprintf("Process %s: pid %d\n", p->name, p->pid);
    }
    spinlock_release(&ptable_lock);
    kprintf("\n");
}
//Removes node from the child_list of a process.
//used as a helper function for proc_wait
void removeChildrenList(struct child_linked_list *node){
    struct proc *p = proc_current();
    struct child_linked_list *head = p->child_list;
    if(head == node){
        p->child_list = p->child_list->next_child;
        return;
    }
    struct child_linked_list *prev;
    while(head != node){
        prev = head;
        head = head->next_child;
    }
    prev->next_child = head->next_child;
}
void
proc_free(struct proc* p)
{
    kmem_cache_free(proc_allocator, p);
}

void
proc_sys_init(void)
{
    list_init(&ptable);
    spinlock_init(&ptable_lock);
    spinlock_init(&pid_lock);
    proc_allocator = kmem_cache_create(sizeof(struct proc));
    kassert(proc_allocator);
    
}

/*
 * Allocate and initialize basic proc structure
*/
static struct proc*
proc_init(char* name)
{
    struct super_block *sb;
    inum_t inum;
    err_t err;

    struct proc *p = proc_alloc();
    if (p == NULL) {
        return NULL;
    }

    if (as_init(&p->as) != ERR_OK) {
        proc_free(p);
        return NULL;
    }

    size_t slen = strlen(name);
    slen = slen < PROC_NAME_LEN-1 ? slen : PROC_NAME_LEN-1;
    memcpy(p->name, name, slen);
    p->name[slen] = 0;

    list_init(&p->threads);

	// cwd for all processes are root for now
    sb = root_sb;
	inum = root_sb->s_root_inum;
    if ((err = fs_get_inode(sb, inum, &p->cwd)) != ERR_OK) {
        as_destroy(&p->as);
        proc_free(p);
        return NULL;
    }

    //Start the file descriptor table
    //0 is stdin
    //1 is stdout
    //The rest is started to null
    p->fdTable[0] = &stdin;
    p->fdTable[1] = &stdout;
    for(int i = 2; i < PROC_MAX_FILE; i++){
        p->fdTable[i] = NULL;
    }

    //Sets linked list of children to null
    p->child_list = NULL;

    //Initializes the needed locks
    condvar_init(&p->wait_cv);
    return p;
}

err_t
proc_spawn(char* name, char** argv, struct proc **p)
{
    err_t err;
    struct proc *proc;
    struct thread *t;
    vaddr_t entry_point;
    vaddr_t stackptr;

    if ((proc = proc_init(name)) == NULL) {
        return ERR_NOMEM;
    }
    // load binary of the process
    if ((err = proc_load(proc, name, &entry_point)) != ERR_OK) {
        goto error;
    }


    // set up stack and allocate its memregion 
    if ((err = stack_setup(proc, argv, &stackptr)) != ERR_OK) {
        goto error;
    }

    if ((t = thread_create(proc->name, proc, DEFAULT_PRI)) == NULL) {
        err = ERR_NOMEM;
        goto error;
    }

    // add to ptable
    spinlock_acquire(&ptable_lock);
    list_append(&ptable, &proc->proc_node);
    spinlock_release(&ptable_lock);

    // set up trapframe for a new process
    tf_proc(t->tf, t->proc, entry_point, stackptr);
    thread_start_context(t, NULL, NULL);

    //Sets up the child and parent list of the child
    if(p != &init_proc){
        spinlock_acquire(&ptable_lock);
        proc->parent = proc_current();
        //Sets up the child structure of the parent
        struct child_linked_list *child_list = kmalloc(sizeof(struct child_linked_list));
        child_list->pid = proc->pid;
        child_list->child_proc = proc;
        child_list->next_child = proc_current()->child_list;
        child_list->returnCode = STATUS_ALIVE;
        proc_current()->child_list = child_list;
        spinlock_release(&ptable_lock);
    }

    // fill in allocated proc
    if (p) {
        *p = proc;
    }


    return ERR_OK;
error:
    as_destroy(&proc->as);
    proc_free(proc);
    return err;
}

//Creates a copy of the current process, sets it as a child of the current process
//And schedules its executions. The process is identical to the current process
struct proc*
proc_fork()
{
    kassert(proc_current());  // caller of fork must be a process
    
    //Creates a new  process that is a copy of the current process and
    //initializes it
    struct proc *p = proc_current();
    struct proc *child_proc;
    struct thread *t;
    child_proc = proc_init(p->name);

    //Copies the address table to the child
    as_copy_as(&p->as, &child_proc->as);

    //Sets up the thread, with return value 0 for child proc
    t = thread_create(child_proc->name, child_proc, DEFAULT_PRI);

    //Copies thread
    *t->tf = *thread_current()->tf;

    //Sets child return value
    tf_set_return(t->tf, 0);
    
    
    // add to ptable
    spinlock_acquire(&ptable_lock);
    list_append(&ptable, &child_proc->proc_node);
    spinlock_release(&ptable_lock);



    //Increments the number of open instances in files
    //and adds them to the child processe's file descriptor table
    for(int i = 0; i < PROC_MAX_FILE; i++){
        if(p->fdTable[i] != NULL){
            child_proc->fdTable[i] = p->fdTable[i];
            fs_reopen_file(p->fdTable[i]); 
        } 
    }

    //Sets up the child and parent list of the child
    child_proc->parent = p;

    //Sets up the child structure of the parent
    spinlock_acquire(&ptable_lock);
    struct child_linked_list *child_list = kmalloc(sizeof(struct child_linked_list));
    child_list->pid = child_proc->pid;
    child_list->child_proc = child_proc;
    child_list->next_child = p->child_list;
    child_list->returnCode = STATUS_ALIVE;
    p->child_list = child_list;
    spinlock_release(&ptable_lock);


    //Schedules the process
    thread_start_context(t, NULL, NULL);

    return child_proc;

}

struct proc*
proc_current()
{
    return thread_current()->proc;
}

void
proc_attach_thread(struct proc *p, struct thread *t)
{
    kassert(t);
    if (p) {
        list_append(&p->threads, &t->thread_node);
    }
}

bool
proc_detach_thread(struct thread *t)
{
    bool last_thread = False;
    struct proc *p = t->proc;
    if (p) {
        list_remove(&t->thread_node);
        last_thread = list_empty(&p->threads);
    }
    return last_thread;
}

//Helper function to proc_wait for when the pid argument
//has value -1. This checks for every child on repeat for
//one that has not yet been read and has a valid return code
//Returns the pid of the child on success
//Returns ERR_CHILD if all the children have already returned or
//have been already waited on
int return_status_minus_one(int* status){
    struct proc *p = proc_current();
    struct child_linked_list *childrenVerify;

    //Iterates through the list of children until it finds
    //One that has returned
    while(1){
        childrenVerify = p->child_list;
        while(childrenVerify != NULL){
            //Returns the address of one child and sets the statu with
            //the child's return status
            if(childrenVerify->returnCode != STATUS_ALIVE){
                if(status != NULL){
                    *status = childrenVerify->returnCode;
                }
                spinlock_acquire(&ptable_lock);
                removeChildrenList(childrenVerify);
                spinlock_release(&ptable_lock);
                return childrenVerify->pid;
            }
            childrenVerify = childrenVerify->next_child;
        }
        if(p->child_list == NULL){
            break;
        }
    }
    return ERR_CHILD;
}

//Suspends execution of the current process until child with pid pid returns
//Sends the exit status of child with pid pid to parent
//If child has already exited returns its exit status
//If pid = -1 waits on any children
//Returns the child pid on success and ERR_CHILD if
//The caller does not have a child with the specified pid.
int
proc_wait(pid_t pid, int* status)
{   
    //Gets linked list of children of the current process
    struct proc *p = proc_current();
    struct child_linked_list *children = p->child_list;

    //Handles edge case of pid = -1
    if(pid == -1){
        return return_status_minus_one(status);
    }

    //Finds the child with pid pid among the list of 
    //child processes and waits for it
    while(children != NULL){
        //processes child with pid pid
        if(children->pid == pid){
            spinlock_acquire(&ptable_lock);
            while(children->returnCode == STATUS_ALIVE){
                condvar_wait(&children->child_proc->wait_cv, &ptable_lock);
            }
            spinlock_release(&ptable_lock);
            //Return status if pointer is not null and removes it from children list
            if(status != NULL){
                *status = children->returnCode;
            }
            spinlock_acquire(&ptable_lock);
            removeChildrenList(children);
            spinlock_release(&ptable_lock);
            return pid;
        }
        children = children->next_child;
    }
    return ERR_CHILD;
}


//Exits the current process with return code status
//The return status is available for the parent process
//This function should not return
void
proc_exit(int status)
{
    struct thread *t = thread_current();
    struct proc *p = proc_current();
    
    // detach current thread, switch to kernel page table
    // free current address space if proc has no more threads
    // order matters here
    proc_detach_thread(t);
    t->proc = NULL;
    vpmap_load(kas->vpmap);
    as_destroy(&p->as);

    // release process's cwd
    fs_release_inode(p->cwd);
 
    //Send the current process's return status to its parent, if parent is not null
    if(p->parent != NULL){
      struct child_linked_list *child_nodes;
      child_nodes = p->parent->child_list;
      //Finds itself on the list of children and updates the return status
      while(child_nodes != NULL){
        if(child_nodes->pid == p->pid){
            child_nodes->returnCode = status;
            spinlock_acquire(&ptable_lock);
            condvar_signal(&child_nodes->child_proc->wait_cv);
            spinlock_release(&ptable_lock);
            child_nodes->child_proc = NULL;
            break;
        }
        child_nodes = child_nodes->next_child;
      }
    }

    //Removes process from list of children
    struct child_linked_list *child_list;
    child_list = p->child_list;
    while(child_list != NULL){
        if(child_list->child_proc != NULL){
            child_list->child_proc->parent = NULL;
            struct child_linked_list *prev = child_list;
            child_list = child_list->next_child;
            kfree(prev);
        }
    }


    //Closes the files (or decrements reference count) in
    //file descriptor table
    for(int i = 0; i < PROC_MAX_FILE; i++){
        if(p->fdTable[i] != NULL){
            fs_close_file(p->fdTable[i]);
            p->fdTable[i] = NULL;
        }
    }

    //Exits thread
    thread_exit(status);
}

/* helper function for loading process's binary into its address space */ 
static err_t
proc_load(struct proc *p, char *path, vaddr_t *entry_point)
{
    int i;
    err_t err;
    offset_t ofs = 0;
    struct elfhdr elf;
    struct proghdr ph;
    struct file *f;
    paddr_t paddr;
    vaddr_t vaddr;
    vaddr_t end = 0;

    if ((err = fs_open_file(path, FS_RDONLY, 0, &f)) != ERR_OK) {
        return err;
    }

    // check if the file is actually an executable file
    if (fs_read_file(f, (void*) &elf, sizeof(elf), &ofs) != sizeof(elf) || elf.magic != ELF_MAGIC) {
        return ERR_INVAL;
    }

    // read elf and load binary
    for (i = 0, ofs = elf.phoff; i < elf.phnum; i++) {
        if (fs_read_file(f, (void*) &ph, sizeof(ph), &ofs) != sizeof(ph)) {
            return ERR_INVAL;
        }
        if(ph.type != PT_LOAD)
            continue;

        if(ph.memsz < ph.filesz || ph.vaddr + ph.memsz < ph.vaddr) {
            return ERR_INVAL;
        }

        memperm_t perm = MEMPERM_UR;
        if (ph.flags & PF_W) {
            perm = MEMPERM_URW;
        }

        // found loadable section, add as a memregion
        struct memregion *r = as_map_memregion(&p->as, pg_round_down(ph.vaddr), 
            pg_round_up(ph.memsz + pg_ofs(ph.vaddr)), perm, NULL, ph.off, False);
        if (r == NULL) {
            return ERR_NOMEM;
        }
        end = r->end;

        // pre-page in code and data, may span over multiple pages
        int count = 0;
        size_t avail_bytes;
        size_t read_bytes = ph.filesz;
        size_t pages = pg_round_up(ph.memsz + pg_ofs(ph.vaddr)) / pg_size;
        // vaddr may start at a nonaligned address
        vaddr = pg_ofs(ph.vaddr);
        while (count < pages) {
            // allocate a physical page and zero it first
            if ((err = pmem_alloc(&paddr)) != ERR_OK) {
                return err;
            }
            vaddr += kmap_p2v(paddr);
            memset((void*)pg_round_down(vaddr), 0, pg_size);
            // calculate how many bytes to read from file
            avail_bytes = read_bytes < (pg_size - pg_ofs(vaddr)) ? read_bytes : (pg_size - pg_ofs(vaddr));
            if (avail_bytes && fs_read_file(f, (void*)vaddr, avail_bytes, &ph.off) != avail_bytes) {
                return ERR_INVAL;
            }
            // map physical page with code/data content to expected virtual address in the page table
            if ((err = vpmap_map(p->as.vpmap, ph.vaddr+count*pg_size, paddr, 1, perm)) != ERR_OK) {
                return err;
            }
            read_bytes -= avail_bytes;
            count++;
            vaddr = 0;
        }
    }
    *entry_point = elf.entry;

    // create memregion for heap after data segment
    if ((p->as.heap = as_map_memregion(&p->as, end, 0, MEMPERM_URW, NULL, 0, 0)) == NULL) {
        return ERR_NOMEM;
    }

    return ERR_OK;
}

err_t
stack_setup(struct proc *p, char **argv, vaddr_t* ret_stackptr)
{
    err_t err;
    paddr_t paddr;
    vaddr_t stackptr;
    vaddr_t stacktop = USTACK_UPPERBOUND-pg_size;

    // allocate a page of physical memory for stack
    if ((err = pmem_alloc(&paddr)) != ERR_OK) {
        return err;
    }
    memset((void*) kmap_p2v(paddr), 0, pg_size);
    // create memregion for stack
    if (as_map_memregion(&p->as, stacktop, pg_size, MEMPERM_URW, NULL, 0, False) == NULL) {
        err = ERR_NOMEM;
        goto error;
    }
    // map in first stack page
    if ((err = vpmap_map(p->as.vpmap, stacktop, paddr, 1, MEMPERM_URW)) != ERR_OK) {
        goto error;
    }
    // kernel virtual address of the user stack, points to top of the stack
    // as you allocate things on stack, move stackptr downward.
    stackptr = kmap_p2v(paddr) + pg_size;

    /* Your Code Here.  */
    // allocate space for fake return address, argc, argv
    // remove following line when you actually set up the stack
    stackptr -= 3 * sizeof(void*);

    // translates stackptr from kernel virtual address to user stack address
    *ret_stackptr = USTACK_ADDR(stackptr); 
    return err;
error:
    pmem_free(paddr);
    return err;
}

