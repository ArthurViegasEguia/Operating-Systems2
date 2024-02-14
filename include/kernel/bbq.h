// Try adding this in include/kernel/
//Written by Tanya Amert

#ifndef __BBQ_H__
#define __BBQ_H__

#include <kernel/synch.h> // this would be something you could actually add to osv

#define MAX_BBQ_SIZE 512

typedef struct {
    // Synchronization variables
    struct spinlock lock;
    struct condvar item_added;
    struct condvar item_removed;

    // State variables
    char items[MAX_BBQ_SIZE];
    int front;
    int next_empty;
} BBQ;

BBQ* bbq_init();
void bbq_free(BBQ *q);
ssize_t bbq_insert(BBQ *q, const void *buff, size_t count);
ssize_t bbq_remove(BBQ *q, void *buf, size_t count);
ssize_t bbq_remove_all(BBQ *q, void *buf);

#endif // __BBQ_H__