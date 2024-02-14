#include <kernel/synch.h>
#include <kernel/pmem.h>
#include <kernel/bdev.h>
#include <kernel/list.h>
#include <kernel/radix_tree.h>
#include <kernel/bbq.h>

//Reads count bytes from a pipe and writes them into buf.
//If there are less bytes in the pipe than count, it reads all the
//bytes from the pipe. If the write side of the pipe is closed, reads
//all the bytes available
//Returns the number of bytes read
ssize_t pipe_read(struct file *file, void *buf, size_t count, offset_t *ofs);

//Writes count bytes from buf into pipe.
//If there are more bytes in the buf than what the pipe can hold
//waists for more free space before it keeps writing.
//Returns ERR_END if the reading side of the pipe is closed
//Returns the number of bytes written otherwise
ssize_t pipe_write(struct file *file, const void *buf, size_t count, offset_t *ofs);

//Closes the end of the pipe represented by f. 
void pipe_close(struct file *f);

//A pipe datastructure, hods a BBQ as a buffer and 
//Has two ends, one for reading and another for writing
typedef struct {
    BBQ *buff;
    struct file *read;
    struct file *write;
} pipe;

//Initializes a new pipe with two open ends
//One writing end and one reading end
//returns pipe on success, NULL otherwise
pipe* pipe_alloc(int *fds);