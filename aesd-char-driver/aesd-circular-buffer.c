/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer implementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.
 * @param char_offset the position to search for in the buffer list
 * @param entry_offset_byte_rtn pointer to store the byte offset within the returned entry
 * @return the struct aesd_buffer_entry for char_offset, or NULL if not available
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(
    struct aesd_circular_buffer *buffer,
    size_t char_offset,
    size_t *entry_offset_byte_rtn)
{
    size_t running = 0;
    uint8_t idx;
    uint8_t count;

    if (!buffer || !entry_offset_byte_rtn)
        return NULL;

    count = buffer->full ? AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED
                         : buffer->in_offs;

    for (idx = 0; idx < count; idx++) {
        uint8_t entry_index = (uint8_t)((buffer->out_offs + idx) %
                               AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);

        struct aesd_buffer_entry *entry = &buffer->entry[entry_index];

        if (!entry->buffptr || entry->size == 0)
            continue;

        if (char_offset < (running + entry->size)) {
            *entry_offset_byte_rtn = char_offset - running;
            return entry;
        }

        running += entry->size;
    }

    return NULL;
}

/**
 * Adds entry @param add_entry to @param buffer at buffer->in_offs.
 * If the buffer was already full, overwrites the oldest entry and returns
 * its buffptr so the caller can free it. Returns NULL if no entry was
 * overwritten.
 */
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer,
                                           const struct aesd_buffer_entry *add_entry)
{
    const char *returnptr = NULL;

    if (!buffer || !add_entry)
        return NULL;

    /* If full, we are about to overwrite the oldest entry — return its pointer */
    if (buffer->full) {
        returnptr = buffer->entry[buffer->in_offs].buffptr;
        buffer->out_offs = (uint8_t)((buffer->out_offs + 1) %
                            AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
    }

    /* Write new entry into current in_offs slot */
    buffer->entry[buffer->in_offs] = *add_entry;

    /* Advance in_offs */
    buffer->in_offs = (uint8_t)((buffer->in_offs + 1) %
                       AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);

    /* If in_offs caught up to out_offs, buffer is now full */
    if (buffer->in_offs == buffer->out_offs)
        buffer->full = true;

    return returnptr;
}

/**
 * Initializes the circular buffer to an empty state
 */
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}
