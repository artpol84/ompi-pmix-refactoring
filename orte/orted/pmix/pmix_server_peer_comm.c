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
 * Copyright (c) 2009      Cisco Systems, Inc.  All rights reserved.
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

#include "orte_config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_NET_UIO_H
#include <net/uio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include "opal/opal_socket_errno.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "opal_stdint.h"
#include "opal/types.h"
#include "opal/mca/backtrace/backtrace.h"
#include "opal/util/output.h"
#include "opal/util/net.h"
#include "opal/util/error.h"
#include "opal/class/opal_hash_table.h"
#include "opal/mca/dstore/dstore.h"
#include "opal/mca/event/event.h"
#include "opal/mca/sec/sec.h"
#include "opal/runtime/opal.h"

#include "orte/util/name_fns.h"
#include "orte/runtime/orte_globals.h"
#include "orte/mca/errmgr/errmgr.h"
#include "orte/mca/ess/ess.h"
#include "orte/mca/grpcomm/grpcomm.h"
#include "orte/mca/rml/rml.h"
#include "orte/mca/routed/routed.h"
#include "orte/mca/state/state.h"
#include "orte/runtime/orte_wait.h"

#include "pmix_server_internal.h"

/* Routines that actually work with UNIX sockets */
static int send_bytes(pmix_server_peer_t* peer)
{
    pmix_server_send_t* msg = peer->send_msg;
    int rc;

    while (0 < msg->sdbytes) {
        rc = write(peer->sd, msg->sdptr, msg->sdbytes);
        if (rc < 0) {
            switch( opal_socket_errno ){
            case EINTR:
                continue;
            case EAGAIN:
                /* Let event lib progress while this socket come to life
                   Both errors will have the same effect, so join them */
                return ORTE_ERR_RESOURCE_BUSY;
            default:
                /* The error is serious and we cannot progress this message */
                opal_output(0, "%s pmix:server:[%s] : write to %s failed: %s (%d) [sd = %d]\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                            ORTE_NAME_PRINT(&(peer->name)), strerror(opal_socket_errno),
                            opal_socket_errno, peer->sd);
                return ORTE_ERR_COMM_FAILURE;
            }
        }
        /* update location */
        msg->sdbytes -= rc;
        msg->sdptr += rc;
    }
    /* we sent the full data block */
    return ORTE_SUCCESS;
}

static int read_bytes(pmix_server_peer_t* peer)
{
    int rc;

    /* read until all bytes recvd or error */
    while (0 < peer->recv_msg->rdbytes) {
        rc = read(peer->sd, peer->recv_msg->rdptr, peer->recv_msg->rdbytes);
        if (rc < 0) {

            switch( opal_socket_errno ){
            case EINTR:
                continue;
            case EAGAIN:
                /* Let event lib progress while this socket come to life
                 Both errors will have the same effect, so join them */
                return ORTE_ERR_RESOURCE_BUSY;
            default:
                /* The error is serious and we cannot progress this message */
                opal_output(0, "%s pmix:server:[%s] : read from %s failed: %s (%d) [sd = %d]\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                            ORTE_NAME_PRINT(&(peer->name)), strerror(opal_socket_errno),
                            opal_socket_errno, peer->sd);
                return ORTE_ERR_COMM_FAILURE;
            }
         } else if (rc == 0)  {
            /* the remote peer closed the connection - report that condition
             and let the caller know */
            opal_output(0, "%s pmix:server:[%s] : peer %s closed connection [sd = %d]\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                        ORTE_NAME_PRINT(&(peer->name)), peer->sd);
            return ORTE_ERR_COMM_FAILURE;
        }
        /* we were able to read something, so adjust counters and location */
        peer->recv_msg->rdbytes -= rc;
        peer->recv_msg->rdptr += rc;
    }

    /* we read the full data block */
    return ORTE_SUCCESS;
}

/*
 * A file descriptor is available/ready for send. Check the state
 * of the socket and take the appropriate action.
 */
void pmix_server_send_handler(int sd, short flags, void *cbdata)
{
    pmix_server_peer_t* peer = (pmix_server_peer_t*)cbdata;
    pmix_server_send_t* msg = peer->send_msg;
    int rc;

    opal_output_verbose(2, pmix_server_output, "%s pmix:server:[%s] : called for %s [sd = %d]\n",
                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                ORTE_NAME_PRINT(&(peer->name)), peer->sd);


    if (NULL != msg) {
        /* if the header hasn't been completely sent, send it */
        if (!msg->hdr_sent) {
            rc = send_bytes(peer);
            /*process errors first (if any)*/
            if (ORTE_SUCCESS != rc ) {
                if (ORTE_ERR_RESOURCE_BUSY == rc) {
                    /* exit this event and let the event lib progress */
                    return;
                } else {
                    /* report the error */
                    opal_output(0, "%s pmix:server:[%s] : unable to send message header to %s [sd = %d]\n",
                                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                                ORTE_NAME_PRINT(&(peer->name)), peer->sd);

                    // ------------------------------------------------8<------------------------------------------------------//
                    // TODO: move all event-dealing code to platform dir
                    opal_event_del(&peer->send_event);
                    peer->send_ev_active = false;
                    OBJ_RELEASE(msg);
                    peer->send_msg = NULL;
                    // ------------------------------------------------8<------------------------------------------------------//
                    goto next;
                }
            }
            /* header is completely sent */
            msg->hdr_sent = true;
            /* setup to send the data */
            if (NULL == msg->data) {
                /* this was a zero-byte msg - nothing more to do */
                OBJ_RELEASE(msg);
                peer->send_msg = NULL;
                goto next;
            } else {
                msg->sdptr = msg->data->base_ptr;
                msg->sdbytes = msg->hdr.nbytes;
            }
        }
        /* progress the data transmission */
        if (msg->hdr_sent) {
            if (ORTE_SUCCESS == (rc = send_bytes(peer))) {
                /* this message is complete */
                OBJ_RELEASE(msg);
                peer->send_msg = NULL;
                /* fall thru to queue the next message */
            } else if (ORTE_ERR_RESOURCE_BUSY == rc ) {
                /* exit this event and let the event lib progress */
                return;
            } else {
                /* report the error */
                opal_output(0, "%s pmix:server:[%s] : unable to send message body to %s [sd = %d]\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                            ORTE_NAME_PRINT(&(peer->name)), peer->sd);
                // ------------------------------------------------8<------------------------------------------------------//
                // TODO: move all event-dealing code to platform dir
                opal_event_del(&peer->send_event);
                peer->send_ev_active = false;
                OBJ_RELEASE(msg);
                peer->send_msg = NULL;
                // ------------------------------------------------8<------------------------------------------------------//
                return;
            }
        }

next:
        /* if current message completed - progress any pending sends by
             * moving the next in the queue into the "on-deck" position. Note
             * that this doesn't mean we send the message right now - we will
             * wait for another send_event to fire before doing so. This gives
             * us a chance to service any pending recvs.
             */
        // ------------------------------------------------8<------------------------------------------------------//
        // TODO: incapsulate opal_list with some pmix wrapper
        peer->send_msg = (pmix_server_send_t*)
                opal_list_remove_first(&peer->send_queue);
        // ------------------------------------------------8<------------------------------------------------------//

    }

    // ------------------------------------------------8<------------------------------------------------------//
    // TODO: move event-dealing code to platform

    /* if nothing else to do unregister for send event notifications */
    if (NULL == peer->send_msg && peer->send_ev_active) {
        opal_event_del(&peer->send_event);
        peer->send_ev_active = false;
    }
    // ------------------------------------------------8<------------------------------------------------------//

}

void pmix_server_recv_handler(int sd, short flags, void *cbdata)
{
    pmix_server_peer_t* peer = (pmix_server_peer_t*)cbdata;
    int rc;

    opal_output_verbose(2, pmix_server_output, "%s pmix:server:[%s] : called for peer %s [sd = %d]\n",
                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                ORTE_NAME_PRINT(&(peer->name)), peer->sd);

    if( NULL == peer->recv_msg ){
        /* allocate a new message and setup for recv */
        opal_output_verbose(2, pmix_server_output,
                    "%s pmix:server:[%s] : allocate new recv msg for peer %s [sd = %d]\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                    ORTE_NAME_PRINT(&(peer->name)), peer->sd);
        peer->recv_msg = OBJ_NEW(pmix_server_recv_t);
        if (NULL == peer->recv_msg) {
            opal_output(0, "%s pmix:server:[%s] : unable to allocate recv message for peer %s [sd = %d]\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                        ORTE_NAME_PRINT(&(peer->name)), peer->sd);
            return;
        }
        /* start by reading the header */
        peer->recv_msg->rdptr = (char*)&peer->recv_msg->hdr;
        peer->recv_msg->rdbytes = sizeof(pmix_server_hdr_t);
    }
    /* if the header hasn't been completely read, read it */
    if (!peer->recv_msg->hdr_recvd) {
        opal_output_verbose(2, pmix_server_output,
                    "%s pmix:server:[%s] : read msg header from peer %s [sd = %d].\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                    ORTE_NAME_PRINT(&(peer->name)), peer->sd);
        rc = read_bytes(peer);
        /* Process errors first (if any) */
        if ( ORTE_SUCCESS != rc ) {
            if (ORTE_ERR_RESOURCE_BUSY == rc ) {
                /* exit this event and let the event lib progress */
                return;
            } else {
                /* close the connection */
                opal_output(0, "%s pmix:server:[%s] : unable to recv message header from %s - closing connection [sd = %d]\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                            ORTE_NAME_PRINT(&(peer->name)), peer->sd);
                int sd = peer->sd;
                pmix_server_peer_disconnect(peer);
                pmix_server_peer_remove(sd);
                return;
            }
        }

        /* completed reading the header */
        peer->recv_msg->hdr_recvd = true;
        opal_output_verbose(2, pmix_server_output,
                    "%s pmix:server:[%s] : received msg header from peer %s [sd = %d]."
                    " Message header's peer is %s\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                    ORTE_NAME_PRINT(&(peer->name)), peer->sd,
                    ORTE_NAME_PRINT((orte_process_name_t*)&(peer->recv_msg->hdr.id)));

        /* if this is a zero-byte message, then we are done */
        if (0 == peer->recv_msg->hdr.nbytes) {
            opal_output_verbose(2, pmix_server_output,
                        "%s pmix:server:[%s] : RECVD ZERO-BYTE MESSAGE from peer %s for tag %d [sd = %d]\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                        ORTE_NAME_PRINT(&(peer->name)), peer->recv_msg->hdr.tag, peer->sd);
            peer->recv_msg->data = NULL;  /* Protect the data */
            peer->recv_msg->rdptr = NULL;
            peer->recv_msg->rdbytes = 0;
        } else {
            opal_output_verbose(2, pmix_server_output,
                        "%s pmix:server:[%s] : allocate data region of size %lu for peer %s [sd = %d]\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                        (unsigned long)peer->recv_msg->hdr.nbytes, ORTE_NAME_PRINT(&(peer->name)), peer->sd);
            /* allocate the data region */
            peer->recv_msg->data = (char*)malloc(peer->recv_msg->hdr.nbytes);
            if (NULL == peer->recv_msg->data ) {
                opal_output(0, "%s pmix:server:[%s] : unable to allocate  data region for peer %s [sd = %d]\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                            ORTE_NAME_PRINT(&(peer->name)), peer->sd);
                return;
            }
            /* point to it */
            peer->recv_msg->rdptr = peer->recv_msg->data;
            peer->recv_msg->rdbytes = peer->recv_msg->hdr.nbytes;
        }

    }

    if (peer->recv_msg->hdr_recvd) {
        /* continue to read the data block - we start from
             * wherever we left off, which could be at the
             * beginning or somewhere in the message
             */
        if (ORTE_SUCCESS == (rc = read_bytes(peer))) {
            /* we recvd all of the message */
            opal_output_verbose(2, pmix_server_output,
                        "%s pmix:server:[%s] : COMPLETE RECVD OF %d BYTES, TAG %d from peer %s [sd = %d]\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                        (int)peer->recv_msg->hdr.nbytes, peer->recv_msg->hdr.tag,
                        ORTE_NAME_PRINT(&(peer->name)), peer->sd);
            /* process the message */
            pmix_server_process_peer(peer);
        } else if (ORTE_ERR_RESOURCE_BUSY == rc ) {
            /* exit this event and let the event lib progress */
            return;
        } else {
            /* report the error */
            opal_output(0, "%s pmix:server:[%s] : unable to recv message body from %s - closing connection [sd = %d]\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__,
                        ORTE_NAME_PRINT(&(peer->name)), peer->sd);
            /* shutdown */
            int sd = peer->sd;
            pmix_server_peer_disconnect(peer);
            pmix_server_peer_remove(sd);
            return;
        }
    }
}
