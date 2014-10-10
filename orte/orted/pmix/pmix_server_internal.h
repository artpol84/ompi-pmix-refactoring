/*
 * Copyright (c) 2004-2007 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2006 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart, 
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2006-2013 Los Alamos National Security, LLC. 
 *                         All rights reserved.
 * Copyright (c) 2010-2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013-2014 Intel, Inc.  All rights reserved. 
 * Copyright (c) 2014      Artem Polyakov <artpol84@gmail.com>.  All rights reserved. 
 * $COPYRIGHT$
 * 
 * Additional copyrights may follow
 * 
 * $HEADER$
 */

#ifndef _PMIX_SERVER_INTERNAL_H_
#define _PMIX_SERVER_INTERNAL_H_

#include "orte_config.h"
#include "orte/types.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include "opal/types.h"
#include "opal/mca/base/base.h"
#include "opal/mca/event/event.h"
#include "opal/mca/pmix/pmix.h"
#include "opal/util/proc.h"

// Include pmix-local files
#include "platform/pmix_peer.h"


BEGIN_C_DECLS

/* define a command type for client-server communications */
typedef uint8_t pmix_cmd_t;
#define PMIX_CMD_T OPAL_UINT8

/* define some commands */
#define PMIX_ABORT_CMD        1
#define PMIX_FENCE_CMD        2
#define PMIX_FENCENB_CMD      3
#define PMIX_PUT_CMD          4
#define PMIX_GET_CMD          5
#define PMIX_GETNB_CMD        6
#define PMIX_FINALIZE_CMD     7
#define PMIX_GETATTR_CMD      8

/* define some message types */
#define PMIX_USOCK_IDENT  1
#define PMIX_USOCK_USER   2



/* object for tracking remote modex requests so we can
 * correctly route the eventual reply */
typedef struct {
    opal_list_item_t super;
    pmix_server_peer_t *peer;
    orte_proc_t *proxy;
    opal_identifier_t target;
    uint32_t tag;
} pmix_server_dmx_req_t;
OBJ_CLASS_DECLARATION(pmix_server_dmx_req_t);

/* queue a message to be sent by one of our procs - must
 * provide the following params:
 *
 * p - the peer object of the process
 * t - tag to be sent to
 * b - buffer to be sent
 */
#define PMIX_SERVER_QUEUE_SEND(p, t, b)                                 \
    do {                                                                \
        pmix_server_send_t *msg;                                        \
        opal_output_verbose(2, pmix_server_output,                      \
                            "%s:[%s:%d] queue send to %s",              \
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),         \
                            __FILE__, __LINE__,                         \
                            ORTE_NAME_PRINT(&(p)->name));               \
        msg = OBJ_NEW(pmix_server_send_t);                              \
        /* setup the header */                                          \
        msg->hdr.id = OPAL_PROC_MY_NAME;                                \
        msg->hdr.type = PMIX_USOCK_USER;                                \
        msg->hdr.tag = (t);                                             \
        msg->hdr.nbytes = (b)->bytes_used;                              \
        /* point to the buffer */                                       \
        msg->data = (b);                                                \
        /* start the send with the header */                            \
        msg->sdptr = (char*)&msg->hdr;                                  \
        msg->sdbytes = sizeof(pmix_server_hdr_t);                     \
        /* if there is no message on-deck, put this one there */        \
        if (NULL == (p)->send_msg) {                                    \
            (p)->send_msg = msg;                                        \
        } else {                                                        \
            /* add it to the queue */                                   \
            opal_list_append(&(p)->send_queue, &msg->super);            \
        }                                                               \
        /* ensure the send event is active */                           \
        if (!(p)->send_ev_active) {                                     \
            opal_event_add(&(p)->send_event, 0);                        \
            (p)->send_ev_active = true;                                 \
        }                                                               \
    }while(0);



/* expose shared functions */
extern void pmix_server_send_handler(int fd, short args, void *cbdata);
extern void pmix_server_recv_handler(int fd, short args, void *cbdata);
extern void pmix_server_recv_handler(int sd, short flags, void *cbdata);

extern int pmix_server_start_listening(struct sockaddr_un *address, int *srv_sd);
extern void pmix_server_connection_handler(int incoming_sd, short flags, void* cbdata);
extern int pmix_server_send_connect_ack(pmix_server_peer_t* peer);
extern int pmix_server_recv_connect_ack(int sd, pmix_server_hdr_t *dhdr);

/* exposed shared variables */
extern bool pmix_server_distribute_data;
extern int pmix_server_verbosity;
extern int pmix_server_output;
extern int pmix_server_local_handle, pmix_server_remote_handle, pmix_server_global_handle;
extern opal_list_t pmix_server_pending_dmx_reqs;

END_C_DECLS

#endif /* PMIX_SERVER_INTERNAL_H_ */

