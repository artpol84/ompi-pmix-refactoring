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
 * Copyright (c) 2014      Artem Polyakov <artpol84@gmail.com>.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 *
 */

#ifndef _PMIX_SERVER_PEER_H_
#define _PMIX_SERVER_PEER_H_

#include "orte_config.h"
#include "orte/types.h"
#include "opal/types.h"
#include "opal/mca/base/base.h"
#include "opal/mca/event/event.h"
#include "opal/class/opal_hash_table.h"
#include "opal/mca/pmix/pmix.h"
#include "orte/orted/pmix/pmix_server_basic.h"

BEGIN_C_DECLS

/* usock structure for sending a message */
typedef struct {
    opal_list_item_t super;
    pmix_server_hdr_t hdr;
    opal_buffer_t *data;
    bool hdr_sent;
    char *sdptr;
    size_t sdbytes;
} pmix_server_send_t;
OBJ_CLASS_DECLARATION(pmix_server_send_t);

/* usock structure for recving a message */
typedef struct {
    opal_list_item_t super;
    pmix_server_hdr_t hdr;
    bool hdr_recvd;
    char *data;
    char *rdptr;
    size_t rdbytes;
} pmix_server_recv_t;
OBJ_CLASS_DECLARATION(pmix_server_recv_t);

/* object for tracking peers - each peer can have multiple
 * connections. This can occur if the initial app executes
 * a fork/exec, and the child initiates its own connection
 * back to the PMIx server. Thus, the trackers are "indexed"
 * by the socket, not the process name */
typedef struct {
    opal_object_t super;
    int sd;
    orte_process_name_t name;
    opal_event_t op_event;      /**< used for connecting and operations other than read/write */
    opal_event_t send_event;    /**< registration with event thread for send events */
    bool send_ev_active;
    opal_event_t recv_event;    /**< registration with event thread for recv events */
    bool recv_ev_active;
    opal_event_t timer_event;   /**< timer for retrying connection failures */
    bool timer_ev_active;
    opal_list_t send_queue;      /**< list of messages to send */
    pmix_server_send_t *send_msg; /**< current send in progress */
    pmix_server_recv_t *recv_msg; /**< current recv in progress */
} pmix_server_peer_t;
OBJ_CLASS_DECLARATION(pmix_server_peer_t);

int pmix_server_peer_init(void);
void pmix_server_peers_destruct(void);
int pmix_server_peers_first(uint64_t *ui64, pmix_server_peer_t **pr, void**next);
int pmix_server_peers_next(uint64_t *ui64, pmix_server_peer_t **pr, void**next);
int pmix_server_peer_add(int sd, pmix_server_peer_t *peer);
int pmix_server_peer_remove(int sd);
void pmix_server_peer_event_init(pmix_server_peer_t* peer, void *recv_cb, void *send_cb);
void pmix_server_peer_connected(pmix_server_peer_t* peer);
pmix_server_peer_t* pmix_server_peer_lookup(int sd);
void pmix_server_peer_disconnect(pmix_server_peer_t *peer);
void pmix_server_peer_dump(pmix_server_peer_t* peer, const char* msg);

END_C_DECLS

#endif /* _PMIX_SERVER_PEER_H_ */
