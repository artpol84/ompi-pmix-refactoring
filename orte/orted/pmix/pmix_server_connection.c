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
 * Copyright (c) 2014      Artem Polyakov <artpol84@gmail.com>.  All rights reserved. 
 * $COPYRIGHT$
 * 
 * Additional copyrights may follow
 * 
 * $HEADER$
 */

#include "orte_config.h"
#include "orte/util/show_help.h"

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

#include "opal/types.h"
#include "opal_stdint.h"
#include "opal/mca/backtrace/backtrace.h"
#include "opal/mca/base/mca_base_var.h"
#include "opal/mca/dstore/dstore.h"
#include "opal/mca/sec/sec.h"
#include "opal/util/output.h"
#include "opal/util/net.h"
#include "opal/util/error.h"
#include "opal/class/opal_hash_table.h"
#include "opal/mca/event/event.h"
#include "opal/runtime/opal.h"

#include "orte/util/name_fns.h"
#include "orte/mca/state/state.h"
#include "orte/runtime/orte_globals.h"
#include "orte/mca/errmgr/errmgr.h"
#include "orte/mca/ess/ess.h"
#include "orte/mca/routed/routed.h"
#include "orte/runtime/orte_wait.h"

#include "pmix_server_internal.h"

// ------------------------------------------------8<------------------------------------------------------//
// TODO: MARK MOVING TO OPAL UTILS
// TRY TO SHARE THIS CODE BETWEEN PMIX CLIENT AND SERVER!
// THUS: make it independent from PMIx server specific data


static int usock_send_blocking(int sd, void* data, size_t size);
static bool usock_recv_blocking(int sd, void* data, size_t size);


/*
 * A blocking send on a non-blocking socket. Used to send the small amount of connection
 * information that identifies the peers endpoint.
 */
static int usock_send_blocking(int sd, void* data, size_t size)
{
    unsigned char* ptr = (unsigned char*)data;
    size_t cnt = 0;
    int retval;

    opal_output_verbose(2, pmix_server_output,
                        "%s usock_peer_send_blocking: of %"PRIsize_t" bytes to socket %d",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), size, sd);

    while (cnt < size) {
        retval = send(sd, (char*)ptr+cnt, size-cnt, 0);
        if (retval < 0) {
            if (opal_socket_errno != EINTR && opal_socket_errno != EAGAIN && opal_socket_errno != EWOULDBLOCK) {
                opal_output(0, "%s usock_peer_send_blocking: send() to socket %d failed: %s (%d)\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd, strerror(opal_socket_errno), opal_socket_errno);
                return ORTE_ERR_UNREACH;
            }
            continue;
        }
        cnt += retval;
    }

    opal_output_verbose(2, pmix_server_output,
                        "%s usock_peer_send_blocking: complete to socket %d",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd);

    return ORTE_SUCCESS;
}

/*
 * A blocking recv on a non-blocking socket. Used to receive the small amount of connection
 * information that identifies the peers endpoint.
 */
static bool usock_recv_blocking(int fd, void* data, size_t size)
{
    unsigned char* ptr = (unsigned char*)data;
    size_t cnt = 0;

    opal_output_verbose(2, pmix_server_output, "%s usock_peer_recv_blocking: start recv on fd = %d",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), fd);

    while (cnt < size) {
        int retval = recv(fd, (char *)ptr+cnt, size-cnt, 0);

        /* remote closed connection */
        if (retval == 0) {
            opal_output_verbose(2, pmix_server_output,
                                "%s usock_peer_recv_blocking: peer closed connection on fd = %d",
                                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), fd );
            return false;
        }

        /* socket is non-blocking so handle errors */
        if (retval < 0) {
            if (opal_socket_errno != EINTR &&
                opal_socket_errno != EAGAIN &&
                opal_socket_errno != EWOULDBLOCK) {
                opal_output(0, "%s usock_peer_recv_blocking: recv() failed on fd = %d: %s (%d)\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), fd,
                            strerror(opal_socket_errno), opal_socket_errno);
                return false;
            }
            continue;
        }
        cnt += retval;
    }

    opal_output_verbose(2, pmix_server_output, "%s usock_peer_recv_blocking: recv() %"PRIsize_t" bytes on fd = %d\n",
                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), size, fd);
    return true;
}

// ------------------------------------------------8<------------------------------------------------------//

int pmix_server_send_connect_ack(pmix_server_peer_t* peer)
{
    opal_sec_cred_t *cred;
    pmix_server_hdr_t hdr;
    size_t sdsize;
    char *msg;
    int rc;

    opal_output_verbose(2, pmix_server_output, "%s pmix_server_send_connect_ack(%s)",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&(peer->name)));

    /* send a handshake that includes our process identifier
     * to ensure we are talking to another OMPI process
    */
    memcpy(&hdr.id, ORTE_PROC_MY_NAME, sizeof(opal_identifier_t));
    hdr.type = PMIX_USOCK_IDENT;
    hdr.tag = UINT32_MAX;

    /* get our security credential*/
    if (OPAL_SUCCESS != (rc = opal_sec.get_my_credential(opal_dstore_internal,
                                                         (opal_identifier_t*)ORTE_PROC_MY_NAME, &cred))) {
        ORTE_ERROR_LOG(rc);
        return rc;
    }

    /* set the number of bytes to be read beyond the header */
    hdr.nbytes = strlen(orte_version_string) + 1 + cred->size;

    /* create a space for our message */
    sdsize = (sizeof(hdr) + hdr.nbytes);
    if (NULL == (msg = (char*)malloc(sdsize))) {
        return ORTE_ERR_OUT_OF_RESOURCE;
    }
    memset(msg, 0, sdsize);

    /* load the message */
    memcpy(msg, &hdr, sizeof(hdr));
    memcpy(msg+sizeof(hdr), opal_version_string, strlen(opal_version_string));
    memcpy(msg+sizeof(hdr)+strlen(opal_version_string)+1, cred->credential, cred->size);

    if (ORTE_SUCCESS != usock_send_blocking(peer->sd, msg, sdsize)) {
        ORTE_ERROR_LOG(ORTE_ERR_UNREACH);
        return ORTE_ERR_UNREACH;
    }
    return ORTE_SUCCESS;
}

/*
 *  Receive the peers globally unique process identification from a newly
 *  connected socket and verify the expected response. If so, move the
 *  socket to a connected state.
 */
int pmix_server_recv_connect_ack(int sd, pmix_server_hdr_t *dhdr)
{
    char *msg = NULL;
    char *version;
    int rc;
    opal_sec_cred_t creds;
    pmix_server_peer_t *peer = NULL;
    pmix_server_hdr_t hdr;
    orte_process_name_t sender;

    opal_output_verbose(2, pmix_server_output,
                        "%s pmix_server_recv_connect_ack(): connect ack from new peer on fd = %d\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd);

    // ensure all is zero'dUINT32_MAX
    memset(&hdr, 0, sizeof(pmix_server_hdr_t));

    if ( !usock_recv_blocking(sd, &hdr, sizeof(pmix_server_hdr_t))) {
        /* unable to complete the recv */
        opal_output_verbose(2, pmix_server_output,
                            "%s pmix_server_recv_connect_ack(): fail to recv header from new peer on fd = %d\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd);
        rc = ORTE_ERR_UNREACH;
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }

    *dhdr = hdr;

    if (hdr.type != PMIX_USOCK_IDENT) {
        opal_output_verbose(2, pmix_server_output,
                            "%s pmix_server_recv_connect_ack(): invalid header type: %d on fd = %d\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), hdr.type, sd);
        rc = ORTE_ERR_UNREACH;
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }

    memcpy(&sender, &hdr.id, sizeof(opal_identifier_t));

    opal_output_verbose(2, pmix_server_output,
                        "%s pmix_server_recv_connect_ack(): header received from %s on fd = %d\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&sender), sd);

    /* get the authentication and version payload */
    if (NULL == (msg = (char*)malloc(hdr.nbytes))) {
        opal_output_verbose(2, pmix_server_output,
                            "%s pmix_server_recv_connect_ack(): out of memory\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        rc = ORTE_ERR_OUT_OF_RESOURCE;
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }

    if ( !usock_recv_blocking(sd, msg, hdr.nbytes) ) {
        opal_output_verbose(2, pmix_server_output,
                            "%s pmix_server_recv_connect_ack(): fail to recv"
                            " message body from %s on fd = %d\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&sender), sd);
        rc = ORTE_ERR_UNREACH;
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }

    // TODO: CHANGE!
    // OPAL version not sufficient anymore
    // We need our own versioning of PMIx protocol!
    /* check that this is from a matching version */
    version = (char*)(msg);
    if (0 != strcmp(version, opal_version_string)) {
        opal_output_verbose(2, pmix_server_output,
                            "%s pmix_server_recv_connect_ack(): version mismatch for %s on fd = %d\n"
                            "\treceived %s instead of %s\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&sender), sd,
                            version, opal_version_string);
        rc = ORTE_ERR_UNREACH;
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }

    opal_output_verbose(2, pmix_server_output,
                        "%s pmix_server_recv_connect_ack(): version check OK for %s on fd = %d\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&sender), sd);

// ------------------------------------------------8<------------------------------------------------------//
    // TODO: MARK FOR REMOVING.
    //      We don't need authentification here.
    //      Unix socket file permissions are enough.
    /* check security token */
    creds.credential = (char*)(msg + strlen(version) + 1);
    creds.size = hdr.nbytes - strlen(version) - 1;
    if (OPAL_SUCCESS != (rc = opal_sec.authenticate(&creds))) {
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }
    free(msg);
// ------------------------------------------------8<------------------------------------------------------//

    opal_output_verbose(2, pmix_server_output,
                        "%s pmix_server_recv_connect_ack(): connect-ack %s authenticated\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&sender));

    return ORTE_SUCCESS;

err_exit:
    if( peer ){
        OBJ_RELEASE(peer);
    }
    return rc;
}

/*
 * start listening on our rendezvous file
 */
int pmix_server_start_listening(struct sockaddr_un *address, int *srv_sd)
{
    int flags;
    opal_socklen_t addrlen;
    int sd = -1;

    /* create a listen socket for incoming connection attempts */
    sd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sd < 0) {
        if (EAFNOSUPPORT != opal_socket_errno) {
            opal_output(0,"pmix_server_start_listening: socket() failed: %s (%d)",
                        strerror(opal_socket_errno), opal_socket_errno);
        }
        return ORTE_ERR_IN_ERRNO;
    }

    addrlen = sizeof(struct sockaddr_un);
    if (bind(sd, (struct sockaddr*)address, addrlen) < 0) {
        opal_output(0, "%s bind() failed on error %s (%d)",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                    strerror(opal_socket_errno),
                    opal_socket_errno );
        CLOSE_THE_SOCKET(sd);
        return ORTE_ERROR;
    }

    /* setup listen backlog to maximum allowed by kernel */
    if (listen(sd, SOMAXCONN) < 0) {
        opal_output(0, "pmix_server_component_init: listen(): %s (%d)",
                    strerror(opal_socket_errno), opal_socket_errno);
        return ORTE_ERROR;
    }

    /* set socket up to be non-blocking, otherwise accept could block */
    if ((flags = fcntl(sd, F_GETFL, 0)) < 0) {
        opal_output(0, "pmix_server_component_init: fcntl(F_GETFL) failed: %s (%d)",
                    strerror(opal_socket_errno), opal_socket_errno);
        return ORTE_ERROR;
    }
    flags |= O_NONBLOCK;
    if (fcntl(sd, F_SETFL, flags) < 0) {
        opal_output(0, "pmix_server_component_init: fcntl(F_SETFL) failed: %s (%d)",
                    strerror(opal_socket_errno), opal_socket_errno);
        return ORTE_ERROR;
    }

    /* record this socket */
    *srv_sd = sd;

    opal_output_verbose(2, pmix_server_output,
                        "%s pmix server listening on socket %d",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd);

    return ORTE_SUCCESS;
}


/*
 * Handler for accepting connections from the event library
 */
void pmix_server_connection_handler(int incoming_sd, short flags, void* cbdata)
{
    struct sockaddr addr;
    opal_socklen_t addrlen = sizeof(struct sockaddr);
    int sd, rc;
    pmix_server_hdr_t hdr;
    pmix_server_peer_t *peer = NULL;

    sd = accept(incoming_sd, (struct sockaddr*)&addr, &addrlen);
    opal_output_verbose(2, pmix_server_output, "%s connection_handler [pmix server]: "
                        "working connection (%d, %d)\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd, opal_socket_errno);

    if (sd < 0) {
        if (EINTR == opal_socket_errno) {
            return;
        }
        if (opal_socket_errno != EAGAIN && opal_socket_errno != EWOULDBLOCK) {
            if (EMFILE == opal_socket_errno) {
                /*
                 * Close incoming_sd so that orte_show_help will have a file
                 * descriptor with which to open the help file.  We will be
                 * exiting anyway, so we don't need to keep it open.
                 */
                CLOSE_THE_SOCKET(incoming_sd);
                ORTE_ERROR_LOG(ORTE_ERR_SYS_LIMITS_SOCKETS);
                orte_show_help("help-orterun.txt", "orterun:sys-limit-sockets", true);
            } else {
                opal_output(0, "%s connection_handler [pmix server]: accept() failed: %s (%d).\n",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                            strerror(opal_socket_errno), opal_socket_errno);
            }
        }
        return;
    }

    // Sanity check: new fd should be in lookup table!
    peer = pmix_server_peer_lookup(sd);
    if (NULL != peer) {
        opal_output_verbose(2, pmix_server_output,
                            "%s connection_handler [pmix server]: WARNING!"
                            " Newly allocated fd = %d is already in the pmix_server_peers.\n"
                            "This shouldn't happen and might be dangerous.",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), sd);
        // Peer might have active send/receive events but we can't call
        // pmix_server_peer_remove since sd is a new descriptor and it will be closed!
        // Do dirty workaround. Maybe we should error exit?
        pmix_server_peer_remove(sd);
        peer = NULL;
    }

    /* get the handshake */
    if (ORTE_SUCCESS != (rc = pmix_server_recv_connect_ack(sd, &hdr))) {
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }

    /* set socket up to be non-blocking */
    if ((flags = fcntl(sd, F_GETFL, 0)) < 0) {
        opal_output(0, "%s connection_handler [pmix server]: fcntl(F_GETFL) failed: %s (%d)\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), strerror(opal_socket_errno), opal_socket_errno);
            // TODO: Shouldn't we error exit here?
    } else {
        flags |= O_NONBLOCK;
        if (fcntl(sd, F_SETFL, flags) < 0) {
            opal_output(0, "%s connection_handler [pmix server]: fcntl(F_SETFL) failed: %s (%d)\n",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), strerror(opal_socket_errno), opal_socket_errno);
            // TODO: Shouldn't we error exit here?
        }
    }

    // Prepare peer structure
    if( NULL == (peer = OBJ_NEW(pmix_server_peer_t) ) ){
        rc = ORTE_ERR_OUT_OF_RESOURCE;
        goto err_exit;
    }
    memcpy(&peer->name, &hdr.id, sizeof(opal_identifier_t));
    peer->sd = sd;
    sd = -1; // we don't want to close this fd through sd anymore

    // TODO: We need to create generic handler to pass it to platform-dependent code,
    // where we will provide proper wrapper
    pmix_server_peer_event_init(peer, (void*)pmix_server_recv_handler, (void*)pmix_server_send_handler);
    // Perform response steps
    if ( ORTE_SUCCESS != (rc = pmix_server_send_connect_ack(peer)) ) {
        opal_output(0, "%s connection_handler [pmix server]: "
                    "usock_peer_send_connect_ack( %s ) failed\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                    ORTE_NAME_PRINT(&(peer->name)));
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }
    pmix_server_peer_connected(peer);

    // Keep track about this peer
    if ( OPAL_SUCCESS != (rc = pmix_server_peer_add(peer->sd, peer)) ) {
        opal_output(0, "%s connection_handler [pmix server]: pmix_server_peer_add( %d, %s ) failed: %s (%d)\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), peer->sd, ORTE_NAME_PRINT(&(peer->name)),
                    strerror(opal_socket_errno), opal_socket_errno);
        OPAL_ERROR_LOG(rc);
        goto err_exit;
    }

    if (2 <= opal_output_get_verbosity(pmix_server_output)) {
        pmix_server_peer_dump(peer, "accepted");
    }
    opal_output(0, "%s connection_handler [pmix server]: "
                "opalpmix_server_peer_add(%d, %s), peer addr %p\n",
                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), peer->sd,
                ORTE_NAME_PRINT(&(peer->name)), (void*)peer);
    // successful return
    return;
err_exit:
    if( peer != NULL ){
        pmix_server_peer_disconnect(peer);
        OBJ_RELEASE(peer);
    }
    if( sd >= 0 ){
        CLOSE_THE_SOCKET(sd);
    }
    return;
}
