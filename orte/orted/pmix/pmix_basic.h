/*
 * Copyright (c) 2004-2010 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2011 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2006-2013 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2009-2012 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011      Oak Ridge National Labs.  All rights reserved.
 * Copyright (c) 2013-2014 Intel, Inc.  All rights reserved.
 * Copyright (c) 2014      Artem Polyakov <artpol84@gmail.com>.  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 *
 */

#ifndef PMIX_BASIC_H
#define PMIX_BASIC_H

#include "opal/class/opal_list.h"

// ------------------------------------------------8<------------------------------------------------------//
// TODO: Schedule transaction to opal/mca/pmix/basic ?!

/* header for pmix client-server msgs - must
 * match that in opal/mca/pmix/native! */
typedef struct {
    opal_identifier_t id;
    uint8_t type;
    uint32_t tag;
    size_t nbytes;
} pmix_server_hdr_t;

// ------------------------------------------------8<------------------------------------------------------//

#define CLOSE_THE_SOCKET(socket)    \
    do {                            \
        shutdown(socket, 2);        \
        close(socket);              \
    } while(0)


typedef struct {
    opal_list_item_t super;
    uint32_t vpid;
    uint32_t cpu_bmp;
} pmix_local_peer_info_t;

typedef struct {
    bool hwloc_on;
    opal_buffer_t hwloc_topo;
    char* cpu_bmap;
    uint32_t jobid;
    uint32_t app_num;
    uint32_t usize;
    uint32_t size;
    uint32_t app_ldr;
    uint32_t rank;
    uint32_t glob_rank;
    uint32_t app_rank;
    uint32_t nproc_offs;
    uint32_t loc_rank;
    uint32_t loc_size;
    uint32_t node_rank;
    uint32_t node_size;
    uint32_t max_procs;
    opal_buffer_t *peers_cpu_bmaps;
    char *peers_list;
} pmix_job_info_t;

#endif // PMIX_BASIC_H
