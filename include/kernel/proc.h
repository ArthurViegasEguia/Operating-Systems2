#ifndef _PROC_H_
#define _PROC_H_

#include <kernel/synch.h>
#include <kernel/vm.h>
#include <kernel/types.h>
#include <kernel/list.h>

#define ANY_CHILD -1
#define STATUS_ALIVE 0xbeefeeb
#define PROC_MAX_ARG 128
#define PROC_NAME_LEN 32
#define PROC_MAX_FILE 128
#define PROC_MAX_CHILDREN 128

//This stuct is a linked list of child processes and useful information to keep
//about them even when they are done executing, such as return code and pid
//Special thanks to Artem Yushko. Discussing with him we came up with this
//It solves problems by our two array approach'
//Special thanks to Artem Yushko, I worked with him throughout this lab
struct child_linked_list;
struct child_linked_list{
    int pid; //Child process PID
    struct proc *child_proc; // Pointer to child proc
    int returnCode; //Integer value of return code
    struct child_linked_list *next_child; //Pointer to the next child on the linked list 
};

struct proc {
    pid_t pid;
    char name[PROC_NAME_LEN]; 
    struct addrspace as;    
    struct inode *cwd;                  // current working directory
    List threads;                       // list of threads belong to the process, right now just 1 per process
    Node proc_node;                     // used by ptable to keep track each process
    struct file *fdTable[PROC_MAX_FILE]; //File descriptor table
    struct proc *parent; //Parent of current process
    struct child_linked_list *child_list; //Linked list of children processes
    struct condvar wait_cv; //Condition variable to wait for this process
};

struct proc *init_proc;


void proc_sys_init(void);

/* Spawn a new process specified by executable name and argument */
err_t proc_spawn(char *name, char** argv, struct proc **p);

/* Fork a new process identical to current process */
struct proc* proc_fork();

/* Return current thread's process. NULL if current thread is not associated with any process */
struct proc* proc_current();

/* Attach a thread to a process. */
void proc_attach_thread(struct proc *proc, struct thread *t);

/* Detach a thread from its process. Returns True if detached thread is the 
 * last thread of the process, False otherwise */
bool proc_detach_thread(struct thread *t);

/*
 * Wait for a process to change state. If pid is ANY_CHILD, wait for any child process.
 * If wstatus is not NULL, store the the exit status of the child in wstatus.
 *
 * Return:
 * pid of the child process that changes state.
 * ERR_CHILD - The caller does not have a child with the specified pid.
 */
int proc_wait(pid_t, int* status);

/* Exit a process with a status */
void proc_exit(int);

#endif /* _PROC_H_ */
