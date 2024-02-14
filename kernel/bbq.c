#include <kernel/kmalloc.h> // again, this could be added to osv
#include <kernel/console.h>
#include "kernel/bbq.h"

// static prevents this variable from being visible outside this file
static struct kmem_cache *bbq_allocator;

// Wait until there is room and then insert count items from buff.
//Returns the number of bytes written intp the pipe
ssize_t bbq_insert(BBQ *q, const void *buff, size_t count)
{
    
    int bytesWritten = 0;
    char *string = (char *) buff;
    spinlock_acquire(&q->lock);

    //Writes count bytes in the pipe
    while(bytesWritten < count){

        // Wait until there is space
        while ((q->next_empty - q->front) == MAX_BBQ_SIZE)
        {
            condvar_wait(&q->item_removed, &q->lock);
        }

        // Add the item
        q->items[q->next_empty % MAX_BBQ_SIZE] = *string;
        q->next_empty++;
        string++;
        bytesWritten++;

    }

    // Signal that it's there
    condvar_signal(&q->item_added);
    spinlock_release(&q->lock);
    return bytesWritten;
}

// Wait until there is are items and then remove up to count items.
ssize_t bbq_remove(BBQ *q, void *buf, size_t count)
{
    char *str = (char *)buf;
    int bytesRead = 0;
    spinlock_acquire(&q->lock);

    while(bytesRead < count && q->front != q->next_empty){
        // Wait until there is something in the queue
        while (q->front == q->next_empty)
        {
            condvar_wait(&q->item_added, &q->lock);
        }

        // Grab the item
        *(str) = q->items[q->front % MAX_BBQ_SIZE];
        str++;
        q->front++;
        bytesRead++;

    }

    // Signal that we removed something
    condvar_signal(&q->item_removed);
    spinlock_release(&q->lock);
    *(str) = '\0';
    return bytesRead;
}

// Initialize the queue to empty, the lock to free, and the
// condition variables to empty.
BBQ* bbq_init()
{
    BBQ *q;

    // If the allocator has not been created yet, do so now
    if (bbq_allocator == NULL)
    {
        if ((bbq_allocator = kmem_cache_create(sizeof(BBQ))) == NULL)
        {
            return NULL;
        }
    }

    // Allocate the BBQ struct
    if ((q = kmem_cache_alloc(bbq_allocator)) == NULL)
    {
        return NULL;
    }

    // Initialize state variables
    q->front = 0;
    q->next_empty = 0;

    // Initialize synchronization variables
    spinlock_init(&q->lock);
    condvar_init(&q->item_added);
    condvar_init(&q->item_removed);

    return q;
}

void bbq_free(BBQ *q)
{
    kmem_cache_free(bbq_allocator, q);
}