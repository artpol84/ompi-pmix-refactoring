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

#include "orte_config.h"
#include "orte/types.h"
#include "opal/types.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <fcntl.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <ctype.h>

#include "opal/util/output.h"

#include "orte/util/name_fns.h"
#include "orte/runtime/orte_globals.h"

#include "orte/orted/pmix/pmix_basic.h"
#include "orte/orted/pmix/platform/pmix_peer.h"

// TODO: This temporal solution to proceed. This should be inside platform coz it is ompi-specific.
// We need to put all debug here.
extern int pmix_server_output;

opal_hash_table_t *pmix_server_peers = NULL;

static void rcon(pmix_server_recv_t *p)
{
    p->data = NULL;
    p->hdr_recvd = false;
    p->rdptr = NULL;
    p->rdbytes = 0;
}
static void rdes(pmix_server_recv_t *p)
{
    if (NULL != p->data) {
        free(p->data);
    }
}

OBJ_CLASS_INSTANCE(pmix_server_recv_t, opal_list_item_t, rcon, rdes);

static void scon(pmix_server_send_t *p)
{
    p->data = NULL;
    p->hdr_sent = false;
    p->sdptr = NULL;
    p->sdbytes = 0;
}
static void dcon(pmix_server_send_t *p)
{
    if (NULL != p->data) {
        OBJ_RELEASE(p->data);
    }
}
OBJ_CLASS_INSTANCE(pmix_server_send_t, opal_list_item_t, scon, dcon);

int pmix_server_peer_init(void)
{
    pmix_server_peers = OBJ_NEW(opal_hash_table_t);
    return opal_hash_table_init(pmix_server_peers, 32);
}

void pmix_server_peers_destruct(void)
{
    if( pmix_server_peers ){
        opal_output_verbose(2, pmix_server_output,
                            "%s: %s [pmix server]: called\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__);
        OBJ_RELEASE(pmix_server_peers);
        pmix_server_peers = NULL;
    }else{
        opal_output_verbose(2, pmix_server_output,
                            "%s: %s [pmix server]: WARNING! Double table destruction!\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__);
    }
}

int pmix_server_peer_add(int sd, pmix_server_peer_t *peer)
{
    uint64_t ui64 = sd;
    return  opal_hash_table_set_value_uint64(pmix_server_peers, ui64, peer);
}

int pmix_server_peers_first(uint64_t *ui64, pmix_server_peer_t **pr, void**next)
{
    return opal_hash_table_get_first_key_uint64(pmix_server_peers, ui64, (void**)pr, next);
}

int pmix_server_peers_next(uint64_t *ui64, pmix_server_peer_t **pr, void**next)
{
    return opal_hash_table_get_next_key_uint64(pmix_server_peers, &ui64, (void**)&pr, *next, &next);
}

int pmix_server_peer_remove(int sd)
{
    int rc;
    pmix_server_peer_t *peer = pmix_server_peer_lookup(sd);
    uint64_t ui64 = sd;

    if( peer == NULL ){
        // Nothing to do. Warn about false remove!
        opal_output_verbose(2, pmix_server_output,
                            "%s pmix:server: WARNING pmix_server_peer_remove(%d) for nonexisting peer\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd);
        return OPAL_SUCCESS;
    }
    if( OPAL_SUCCESS != ( rc = opal_hash_table_remove_value_uint64(pmix_server_peers, ui64) ) ){
        return rc;
    }
    OBJ_RELEASE(peer);
    return OPAL_SUCCESS;
}

void pmix_server_peer_event_init(pmix_server_peer_t* peer, void *recv_cb, void *send_cb)
{
    if (peer->sd >= 0) {
        opal_event_set(orte_event_base,
                       &peer->recv_event,
                       peer->sd,
                       OPAL_EV_READ|OPAL_EV_PERSIST,
                       (event_callback_fn)recv_cb,
                       peer);
        opal_event_set_priority(&peer->recv_event, ORTE_MSG_PRI);
        if (peer->recv_ev_active) {
            opal_event_del(&peer->recv_event);
            peer->recv_ev_active = false;
        }

        opal_event_set(orte_event_base,
                       &peer->send_event,
                       peer->sd,
                       OPAL_EV_WRITE|OPAL_EV_PERSIST,
                       (event_callback_fn)send_cb,
                       peer);
        opal_event_set_priority(&peer->send_event, ORTE_MSG_PRI);
        if (peer->send_ev_active) {
            opal_event_del(&peer->send_event);
            peer->send_ev_active = false;
        }
    }
}

/*
 *  Setup peer state to reflect that connection has been established,
 *  and start any pending sends.
 */
void pmix_server_peer_connected(pmix_server_peer_t* peer)
{
    opal_output_verbose(2, pmix_server_output,
                        "%s-%s usock_peer_connected on socket %d",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                        ORTE_NAME_PRINT(&(peer->name)), peer->sd);

    if (peer->timer_ev_active) {
        opal_event_del(&peer->timer_event);
        peer->timer_ev_active = false;
    }

    /* ensure the recv event is active */
    if (!peer->recv_ev_active) {
        opal_event_add(&peer->recv_event, 0);
        peer->recv_ev_active = true;
    }

    /* initiate send of first message on queue */
    if (NULL == peer->send_msg) {
        peer->send_msg = (pmix_server_send_t*)
            opal_list_remove_first(&peer->send_queue);
    }
    if (NULL != peer->send_msg && !peer->send_ev_active) {
        opal_event_add(&peer->send_event, 0);
        peer->send_ev_active = true;
    }
}

void pmix_server_peer_disconnect(pmix_server_peer_t* peer)
{
    // If the peer is in 'pmix_server_peers' hash table
    // it will remain there in case it will try again
    if (peer->recv_ev_active) {
        opal_event_del(&peer->recv_event);
        peer->recv_ev_active = false;
    }
    if (peer->send_ev_active) {
        opal_event_del(&peer->send_event);
        peer->send_ev_active = false;
    }

    if (peer->timer_ev_active) {
        opal_event_del(&peer->timer_event);
        peer->timer_ev_active = false;
    }

    if (NULL != peer->recv_msg) {
        OBJ_RELEASE(peer->recv_msg);
        peer->recv_msg = NULL;
    }

    if (peer->sd >= 0) {
        CLOSE_THE_SOCKET(peer->sd);
        peer->sd = -1;
    }
}

pmix_server_peer_t* pmix_server_peer_lookup(int sd)
{
    pmix_server_peer_t *peer;
    uint64_t ui64;

    ui64 = sd;
    if (OPAL_SUCCESS != opal_hash_table_get_value_uint64(pmix_server_peers, ui64, (void**)&peer)) {
        return NULL;
    }
    return peer;
}


