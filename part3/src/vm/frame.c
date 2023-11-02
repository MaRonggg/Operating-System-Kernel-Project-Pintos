#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"

// The hash structure that represents our frame table
static struct hash frame_hash_table;

static struct lock frame_lock;    // synchronization variable for the frame table (hash table)
static bool initial_load = false; // a flag set once we've initialized, to ensure no re-initialization

/**
Initializes the hash for the frame table and the lock used
for ensuring thread safety when handling frames (since they
are in active use and would be thus dangerous to touch).
 */
void init_frame_table(void)
{
    if (!initial_load)
    {
        // TODO: IMPLEMENT YOUR HASH WITH THE hash_init() FUNCTION AND THE frame_hash_table VARIABLE
        hash_init(&frame_hash_table, frame_hash, frame_less, NULL);

        lock_init(&frame_lock);
        initial_load = true;    
    }

    return;
}

/**
Looks within the global frame table to see if it has an entry
that corresponds to the passed frame. Returns it if so. Returns
NULL if no match was found.
 */
struct frame_table_entry *get_frame_entry(void *frame_ptr)
{

    // TODO: IMPLEMENT RETRIEVAL OF A FRAME ENTRY, WHICH WILL BE WITHIN THE HASH TABLE.
    init_frame_table();

    struct frame_table_entry f;
    struct hash_elem *e;

    f.frame_addr = frame_ptr;
    e = hash_find (&frame_hash_table, &f.frame_elem);
    return e != NULL ? hash_entry (e, struct frame_table_entry, frame_elem) : NULL;
}

/**
 *
Request a frame from the kernel to put the passed in page entry into.
This function does not take into account when palloc_get_page is not able to give
a page, in which a frame would need to have its page evicted for the allocation
to complete.
Returns the frame entry after placing it into the frame table hash and
setting its struct variables as appropriate.
mapped_page - The supplemental_page_table_entry that is associated with this frame currently.
frame_addr - The kernel page address that was given- the frame address.
Synchronization is important to use when working with frames (see init function comment).
 */
struct frame_table_entry *allocate_frame(struct supplemental_page_table_entry *pg)
{
    init_frame_table();

    struct frame_table_entry *entry = NULL;
    lock_acquire(&frame_lock);

    void *ptr = palloc_get_page(PAL_USER);

    entry = malloc(sizeof(struct frame_table_entry));
    entry->holder = thread_current();
    entry->mapped_page = pg;
    entry->frame_addr = ptr;

    // TODO: IMPLEMENT PLACEMENT OF THIS ALLOCATED FRAME WITHIN THE FRAME TABLE
    hash_insert(&frame_hash_table, &entry->frame_elem);

    lock_release(&frame_lock);
    return entry;
}

/**
Removes the specified frame contents. Aquires lock before doing so
for obvious synchronization reasons. Gives the memory back to the kernel.
 */
void remove_frame(struct frame_table_entry *frame)
{
    lock_acquire(&frame_lock);

    if (frame != NULL)
    {
        // TODO: IMPLEMENT REMOVAL OF THIS ENTRY FROM THE FRAME TABLE
        hash_delete(&frame_hash_table, &frame->frame_elem);

        palloc_free_page(frame->frame_addr);
        free(frame);
    }

    lock_release(&frame_lock);
}

unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame_table_entry *f = hash_entry (f_, struct frame_table_entry, frame_elem);
  return hash_bytes (&f->frame_addr, sizeof f->frame_addr);
}

bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct frame_table_entry *a = hash_entry (a_, struct frame_table_entry, frame_elem);
  const struct frame_table_entry *b = hash_entry (b_, struct frame_table_entry, frame_elem);

  return a->frame_addr < b->frame_addr;
}