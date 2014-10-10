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

#endif // PMIX_BASIC_H
