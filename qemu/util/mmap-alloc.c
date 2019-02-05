/*
 * Support for RAM backed by mmaped host memory.
 *
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/mmap-alloc.h"
#include "qemu/host-utils.h"
#include <sys/mman.h>

void *qemu_ram_mmap(int fd, size_t size, size_t align, bool shared)
{
    int flags;
    int guardfd;
    size_t offset;
    size_t total;
    void *guardptr;
    void *ptr;

     /*
      * Note: this always allocates at least one extra page of virtual address
      * space, even if size is already aligned.
      */
    total = size + align;

 #if defined(__powerpc64__) && defined(__linux__)
     /* On ppc64 mappings in the same segment (aka slice) must share the same
      * page size. Since we will be re-allocating part of this segment
      * from the supplied fd, we should make sure to use the same page size, to
      * this end we mmap the supplied fd.  In this case, set MAP_NORESERVE to
      * avoid allocating backing store memory.
      * We do this unless we are using the system page size, in which case
      * anonymous memory is OK.
      */
    flags = MAP_PRIVATE;
    if (fd == -1 || qemu_fd_getpagesize(fd) == getpagesize()) {
        guardfd = -1;
        flags |= MAP_ANONYMOUS;
    } else {
        guardfd = fd;
        flags |= MAP_NORESERVE;
    }
 #else
    guardfd = -1;
    flags = MAP_PRIVATE | MAP_ANONYMOUS;
 #endif
    guardptr = mmap(0, total, PROT_NONE, flags, guardfd, 0);

    if (guardptr == MAP_FAILED) {
        return MAP_FAILED;
    }

    /* Make sure align is a power of 2 */
    assert(is_power_of_2(align));
    /* Always align to host page size */
    assert(align >= getpagesize());

    flags = MAP_FIXED;
    flags |= fd == -1 ? MAP_ANONYMOUS : 0;
    flags |= shared ? MAP_SHARED : MAP_PRIVATE;
    offset = QEMU_ALIGN_UP((uintptr_t)guardptr, align) - (uintptr_t)guardptr;

    ptr = mmap(guardptr + offset, size, PROT_READ | PROT_WRITE, flags, fd, 0);

    if (ptr == MAP_FAILED) {
        munmap(guardptr, total);
        return MAP_FAILED;
    }

    if (offset > 0) {
        munmap(guardptr, offset);
    }

    /*
     * Leave a single PROT_NONE page allocated after the RAM block, to serve as
     * a guard page guarding against potential buffer overflows.
     */
    total -= offset;
    if (total > size + getpagesize()) {
        munmap(ptr + size + getpagesize(), total - size - getpagesize());
    }

    return ptr;
}

void qemu_ram_munmap(void *ptr, size_t size)
{
    if (ptr) {
        /* Unmap both the RAM block and the guard page */
        munmap(ptr, size + getpagesize());
    }
}
