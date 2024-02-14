#include <kernel/kmalloc.h> // again, this could be added to osv
#include <kernel/fs.h>
#include <kernel/proc.h>
#include <kernel/thread.h>
#include <kernel/console.h>
#include <lib/syscall-num.h>
#include <lib/errcode.h>
#include <lib/stddef.h>
#include <lib/string.h>
#include <arch/asm.h>
#include "kernel/pipe.h"
#include "kernel/bbq.h"
#include "kernel/proc.h"

static struct file_operations pipe_ops = {
    .read = pipe_read,
    .write = pipe_write,
    .close = pipe_close
};

//Initializes a new pipe with two open ends,
//one writing end, and one reading end.
//Returns pipe on success, NULL otherwise.
pipe* pipe_alloc(int *fds){
    struct proc *proc = proc_current();
    pipe *p;
    struct file *read, *write;

    //Allocates the pipe and its reading and writing ends, returns null if there is not enough memory
    if(((p = kmalloc(sizeof(pipe))) == NULL) || ((read = fs_alloc_file()) == NULL) 
        || ((write = fs_alloc_file()) == NULL)){
        return NULL;
    }

    //Initializes the file descriptors and sets them as the reading and
    //Writing ends of the pipe. Initializes the BBQ as a buffer,
    //And puts them in the appropriate fields of the pipe
    read->oflag = FS_RDONLY;
    write->oflag = FS_WRONLY;
    read->f_inode = NULL;
    write->f_inode = NULL;
    read->f_ops = &pipe_ops;
    write->f_ops = &pipe_ops;
    read->info = p;
    write->info = p;
    read->f_pos = 0;
    write->f_pos = 0;
    p->read = read;
    p->write = write;
    p->buff = bbq_init();

    //Finds two possible fds values. If none are available, returns null.
    //These will be the read and write position on the fd table respectively
    int i;
    fds[0] = -1;
    fds[1] = -1;
    for(i = 0; i < PROC_MAX_FILE; i++){
        if(proc->fdTable[i] == NULL){
            fds[0] = i;
            proc->fdTable[i] = read;
            break;
        }
    }
    for(i = 0; i < PROC_MAX_FILE; i++){
        if(proc->fdTable[i] == NULL){
            fds[1] = i;
            proc->fdTable[i] = write;
            break;
        }
    }
    if(fds[1] == -1){
        //Handles the edge case of only finding one available fd
        if(fds[0] != -1){
            proc->fdTable[fds[0]] = NULL;
        }
        return NULL;
    }

    return p;
}

//Closes the end of the pipe that is represented
//by file f
void pipe_close(struct file *f){
    pipe *p = f->info;

    //If it is the reading end of the pipe, closes it
    if(p->read != NULL && p->read == f){
        p->read = NULL;
    }

    //If it is the writing end of the pipe, closes it
    if(p->write != NULL && p->write == f){
        p->write = NULL;
    }

    if(p->write == NULL && p->read == NULL){
        kfree(p);
    }
}

//Reads count bytes from a pipe and writes them into buf.
//If there are less bytes in the pipe than count, it reads all the
//bytes from the pipe. If the write side of the pipe is closed, reads
//all the bytes available
//Returns the number of bytes read
ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs){
    pipe *p = (pipe *)file->info;
    if(p->write != NULL){
        return  bbq_remove(p->buff, buf, count);
    }
    //Handles case where write end is closed and it reads all
    //bytes from the pipe
    return bbq_remove(p->buff, buf, MAX_BBQ_SIZE);
}

//Writes count bytes from buf into pipe.
//If there are more bytes in the buf than what the pipe can hold
//waists for more free space before it keeps writing.
//Returns ERR_END if the reading side of the pipe is closed
//Returns the number of bytes written otherwise
ssize_t pipe_write(struct file *file, const void *buf, size_t count, offset_t *ofs){
    pipe *p = (pipe *)file->info;
    if(p->read != NULL){
        return bbq_insert(p->buff, buf, count);
    }
    return ERR_END;
}