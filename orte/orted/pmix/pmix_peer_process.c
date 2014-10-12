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

#include "opal_stdint.h"
#include "opal/class/opal_list.h"
#include "opal/mca/base/mca_base_var.h"
//#include "opal/util/opal_environ.h"
//#include "opal/util/show_help.h"
#include "opal/util/output.h"
//#include "opal/opal_socket_errno.h"
//#include "opal/util/if.h"
//#include "opal/util/net.h"
//#include "opal/util/argv.h"
#include "opal/mca/dstore/dstore.h"

#include "orte/mca/state/state.h"
#include "orte/mca/errmgr/errmgr.h"
#include "orte/mca/grpcomm/grpcomm.h"
#include "orte/mca/rml/rml.h"
#include "orte/util/name_fns.h"
#include "orte/runtime/orte_globals.h"

#include "pmix_basic.h"
#include "platform/pmix_peer.h"
#include "platform/pmix_platform.h"
//#include "pmix_server.h"
#include "pmix_server_internal.h"



/* stuff proc attributes for sending back to a proc */
int pmix_server_proc_info(opal_buffer_t *reply, pmix_server_pm_handler_t *pm)
{
    orte_process_name_t name;
    pmix_job_info_t jinfo;
    opal_value_t kv, *kp;
    int rc;

    if( OPAL_SUCCESS != ( rc = pmix_server_proc_info_pm(pm, &jinfo) ) ){
        opal_output(0, "%s %s: Cannot get job information from platform-dependent code.\n",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), __FUNCTION__);
        return rc;
    }

    kp = &kv;

    if( jinfo.hwloc_on ){
        OBJ_CONSTRUCT(&kv, opal_value_t);
        kv.key = strdup(PMIX_LOCAL_TOPO);
        kv.type = OPAL_BYTE_OBJECT;
        opal_dss.unload(&jinfo.hwloc_topo, (void**)&kv.data.bo.bytes, &kv.data.bo.size);
        OBJ_DESTRUCT(&jinfo.hwloc_topo);
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&kv);
            return rc;
        }
        OBJ_DESTRUCT(&kv);
    }

    /* cpuset */
    if( NULL != jinfo.cpu_bmap ){
        PMIX_ADD_KP(kp, reply, PMIX_CPUSET, string, jinfo.cpu_bmap, err_exit );
    }

    /* jobid */
    PMIX_ADD_KP(kp, reply, PMIX_JOBID, uint32, jinfo.jobid, err_exit );
    /* appnum */
    PMIX_ADD_KP(kp, reply, PMIX_APPNUM, uint32, jinfo.app_num, err_exit );
    /* rank */
    PMIX_ADD_KP(kp, reply, PMIX_RANK, uint32, jinfo.rank, err_exit );
    /* global rank */
    PMIX_ADD_KP(kp, reply, PMIX_GLOBAL_RANK, uint32, jinfo.glob_rank, err_exit );
    /* app rank */
    PMIX_ADD_KP(kp, reply, PMIX_APP_RANK, uint32, jinfo.app_rank, err_exit );
    /* offset */
    PMIX_ADD_KP(kp, reply, PMIX_NPROC_OFFSET, uint32, jinfo.nproc_offs, err_exit );
    /* local rank */
    PMIX_ADD_KP(kp, reply, PMIX_LOCAL_RANK, uint32, jinfo.loc_rank, err_exit );
    /* node rank */
    PMIX_ADD_KP(kp, reply, PMIX_NODE_RANK, uint32, jinfo.node_rank, err_exit );
    /* pass the local ldr */
    PMIX_ADD_KP(kp, reply, PMIX_LOCALLDR, uint32, *(uint64_t*)&name, err_exit );
    /* app ldr */
    PMIX_ADD_KP(kp, reply, PMIX_APPLDR, uint32, jinfo.app_ldr, err_exit );
    /* univ size */
    PMIX_ADD_KP(kp, reply, PMIX_UNIV_SIZE, uint32, jinfo.usize, err_exit );
    /* job size */
    PMIX_ADD_KP(kp, reply, PMIX_JOB_SIZE, uint32, jinfo.size, err_exit );
    /* local size */
    PMIX_ADD_KP(kp, reply, PMIX_LOCAL_SIZE, uint32, jinfo.loc_size, err_exit );
    /* node size */
    PMIX_ADD_KP(kp, reply, PMIX_NODE_SIZE, uint32, jinfo.node_rank, err_exit );
    /* max procs */
    PMIX_ADD_KP(kp, reply, PMIX_MAX_PROCS, uint32, jinfo.max_procs, err_exit );
    /* construct the list of local peers */
    PMIX_ADD_KP(kp, reply, PMIX_LOCAL_PEERS, string, jinfo.peers_list, err_exit );

    /* pass the blob containing the cpusets for all local peers - note
     * that the cpuset of the proc we are responding to will be included,
     * so we don't need to send it separately */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_LOCAL_CPUSETS);
    kv.type = OPAL_BYTE_OBJECT;
    opal_dss.unload(jinfo.peers_cpu_bmaps, (void**)&kv.data.bo.bytes, &kv.data.bo.size);
    // TODO: Shouldn't be done here. must be done in platform code
    OBJ_RELEASE(jinfo.peers_cpu_bmaps);

    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);


    /* local topology - we do this so the procs won't read the
     * topology themselves as this could overwhelm the local
     * system on large-scale SMPs */

    return ORTE_SUCCESS;
err_exit:
    return rc;
}

int
pmix_server_append_pending_dmx(pmix_server_pm_handler_t *pm, pmix_server_peer_t *peer,
                               opal_identifier_t idreq, uint32_t tag)
{
    pmix_server_dmx_req_t *req = NULL;
    int rc;

    /* track the request */
    req = OBJ_NEW(pmix_server_dmx_req_t);
    if( NULL == req ){
        rc = ORTE_ERR_OUT_OF_RESOURCE;
        ORTE_ERROR_LOG(rc);
        return rc;
    }

    OBJ_RETAIN(peer);  // just to be safe
    req->peer = peer;
    req->target = idreq;
    req->tag = tag;
    opal_list_append(&pmix_server_pending_dmx_reqs, &req->super);
    return ORTE_SUCCESS;
}

inline static int _track_unknown_proc(pmix_server_pm_handler_t *pm, pmix_server_peer_t *peer,
                               opal_identifier_t idreq, uint32_t tag, opal_buffer_t **_reply)
{
    pmix_server_dmx_req_t *req;
    opal_buffer_t *reply = NULL;
    bool found = false;
    int rc, ret;

    // Zero reply in case we don't need it
    *_reply = NULL;

    /* are we already tracking it? */
    OPAL_LIST_FOREACH(req, &pmix_server_pending_dmx_reqs, pmix_server_dmx_req_t) {
        if (idreq == req->target) {
            /* yes, so we don't need to send another request, but
             * we do need to track that this peer also wants
             * a copy */
            found = true;
            break;
        }
    }

    if( ORTE_SUCCESS != pmix_server_append_pending_dmx(pm, peer, idreq, tag) ){
        goto err_cleanup;
    }

    if (!found) {
        /* this is a new tracker - see if we need to send a data
         * request to some remote daemon to resolve it */
        if (!ORTE_FLAG_TEST(pm->proc, ORTE_PROC_FLAG_LOCAL)) {

            /* If we are hosting this proc*/
            if (NULL == pm->proc->node || NULL == pm->proc->node->daemon) {
                // FIXME: Should it be "we hos_t_ed - ... "?
                //      Actually what we can conclude from
                //      (NULL == pm->proc->node || NULL == pm->proc->node->daemon)?
                /* we are hosed - pack an error and return it */
                reply = OBJ_NEW(opal_buffer_t);
                ret = ORTE_ERR_NOT_FOUND;
                if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
                    ORTE_ERROR_LOG(rc);
                    goto err_cleanup;
                }
                *_reply = reply;
                return ORTE_SUCCESS;
            }

            /* If this is the remote daemon */
            reply = OBJ_NEW(opal_buffer_t);
            /* pack the proc we want info about */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &idreq, 1, OPAL_UINT64))) {
                ORTE_ERROR_LOG(rc);
                goto err_cleanup;
            }

            // FIXME: Is this correct comment?
            /* pmix_server_start_listening end the request - the recv will come back elsewhere
             * and reply to the original requestor */
            orte_rml.send_buffer_nb(&pm->proc->node->daemon->name, reply,
                                    ORTE_RML_TAG_DIRECT_MODEX,
                                    orte_rml_send_callback, NULL);
            return ORTE_SUCCESS;
        }
    }
    return ORTE_SUCCESS;
err_cleanup:
    if( NULL != reply ){
        OBJ_RELEASE(reply);
    }
    *_reply = NULL;
    return rc;
}

inline static int _reply_for_local_proc(pmix_server_pm_handler_t *pm, opal_identifier_t idreq,
                                 opal_buffer_t **_reply)
{
    opal_value_t *kvp = NULL, *kvp2 = NULL;
    opal_value_t kv, *kp = &kv;
    opal_list_t values;
    opal_buffer_t *reply = NULL;
    opal_buffer_t buf, *bptr = NULL;
    int ret = 0, rc = 0;

    // Initialize reply with zero just in case;
    *_reply = NULL;

    opal_output_verbose(2, pmix_server_output, "%s recvd GET PROC %s IS LOCAL",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&pm->name));

    /* retrieve the local blob for that proc */
    OBJ_CONSTRUCT(&values, opal_list_t);
    if (OPAL_SUCCESS == (ret = opal_dstore.fetch(pmix_server_local_handle, &idreq, "modex", &values))) {
        kvp = (opal_value_t*)opal_list_remove_first(&values);
    } else {
        OPAL_LIST_DESTRUCT(&values);
        goto err_reply;
    }
    OPAL_LIST_DESTRUCT(&values);

    /* retrieve the global blob for that proc */
    OBJ_CONSTRUCT(&values, opal_list_t);
    if (OPAL_SUCCESS == (ret = opal_dstore.fetch(pmix_server_global_handle, &idreq, "modex", &values))) {
        kvp2 = (opal_value_t*)opal_list_remove_first(&values);
    } else {
        OPAL_LIST_DESTRUCT(&values);
        goto err_reply;
    }
    OPAL_LIST_DESTRUCT(&values);

    /* return it */
    reply = OBJ_NEW(opal_buffer_t);
    /* pack the status */
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
        ORTE_ERROR_LOG(rc);
        goto err_cleanup;
    }

    /* pass the hostname */
    OBJ_CONSTRUCT(&buf, opal_buffer_t);
    PMIX_ADD_KP(kp, &buf, PMIX_HOSTNAME, string, strdup(orte_process_info.nodename), err_add_kv );
    bptr = &buf;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
        ORTE_ERROR_LOG(rc);
        goto err_add_kv;
    }
    OBJ_DESTRUCT(&buf);

    /* local blob */
    if (NULL != kvp) {
        opal_output_verbose(2, pmix_server_output,
                            "%s passing local blob of size %d from proc %s to proc %s",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), (int)kvp->data.bo.size,
                            ORTE_NAME_PRINT((orte_process_name_t*)&idreq), ORTE_NAME_PRINT(&pm->name));
        OBJ_CONSTRUCT(&buf, opal_buffer_t);
        opal_dss.load(&buf, kvp->data.bo.bytes, kvp->data.bo.size);
        /* protect the data */
        kvp->data.bo.bytes = NULL;
        kvp->data.bo.size = 0;
        OBJ_RELEASE(kvp);

        bptr = &buf;
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
            ORTE_ERROR_LOG(rc);
            goto err_add_kv;
        }
        OBJ_DESTRUCT(&buf);
    }
    /* global blob */
    if (NULL != kvp2) {
        opal_output_verbose(2, pmix_server_output,
                            "%s passing global blob of size %d from proc %s to proc %s",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), (int)kvp->data.bo.size,
                            ORTE_NAME_PRINT((orte_process_name_t*)&idreq), ORTE_NAME_PRINT(&pm->name));
        OBJ_CONSTRUCT(&buf, opal_buffer_t);
        opal_dss.load(&buf, kvp2->data.bo.bytes, kvp2->data.bo.size);
        /* protect the data */
        kvp2->data.bo.bytes = NULL;
        kvp2->data.bo.size = 0;
        OBJ_RELEASE(kvp2);

        bptr = &buf;
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
            ORTE_ERROR_LOG(rc);
            goto err_add_kv;
        }
        OBJ_DESTRUCT(&buf);

    }

    *_reply = reply;
    return ORTE_SUCCESS;

err_reply:
    reply = OBJ_NEW(opal_buffer_t);
    /* pack the status */
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
        ORTE_ERROR_LOG(rc);
        goto err_cleanup;
    }
    *_reply = reply;
    return ret;

err_add_kv:
    OBJ_DESTRUCT(&buf);

err_cleanup:
    if( reply ){
        OBJ_RELEASE(reply);
    }
    *_reply = NULL;
    return rc;
}


static inline int
_reply_for_remote_proc(pmix_server_pm_handler_t *pm, opal_identifier_t idreq, opal_buffer_t **_reply)
{
    opal_buffer_t buf, *reply = NULL;
    opal_value_t *kvp = NULL;
    opal_list_t values;
    int ret, rc;

    opal_output_verbose(2, pmix_server_output,
                        "%s recvd GET PROC %s IS NON-LOCAL",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                        ORTE_NAME_PRINT(&pm->name));

    /* since we already have this proc's data, we know that the
     * entire blob is stored in the remote handle - so get it */
    OBJ_CONSTRUCT(&values, opal_list_t);
    if (OPAL_SUCCESS == (ret = opal_dstore.fetch(pmix_server_remote_handle, &idreq, "modex", &values))) {
        kvp = (opal_value_t*)opal_list_remove_first(&values);
    } else {
        OPAL_LIST_DESTRUCT(&values);
        goto err_reply;
    }
    OPAL_LIST_DESTRUCT(&values);

    opal_output_verbose(2, pmix_server_output, "%s passing blob of size %d from remote proc %s to proc %s",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), (int)kvp->data.bo.size,
                        ORTE_NAME_PRINT((orte_process_name_t*)&idreq), ORTE_NAME_PRINT(&pm->name));

    OBJ_CONSTRUCT(&buf, opal_buffer_t);
    opal_dss.load(&buf, kvp->data.bo.bytes, kvp->data.bo.size);
    /* protect the data */
    kvp->data.bo.bytes = NULL;
    kvp->data.bo.size = 0;
    OBJ_RELEASE(kvp);

    reply = OBJ_NEW(opal_buffer_t);
    /* pack the status */
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
        ORTE_ERROR_LOG(rc);
        goto err_add_kv;
    }
    /* xfer the data - the blobs are in the buffer,
     * so don't repack them. They will include the remote
     * hostname, so don't add it again */
    opal_dss.copy_payload(reply, &buf);
    OBJ_DESTRUCT(&buf);
    *_reply = reply;
    return ORTE_SUCCESS;
err_reply:
    reply = OBJ_NEW(opal_buffer_t);
    /* pack the status */
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
        ORTE_ERROR_LOG(rc);
        goto err_cleanup;
    }
    *_reply = reply;
    return ret;

err_add_kv:
    OBJ_DESTRUCT(&buf);
err_cleanup:
    if( reply ){
        OBJ_RELEASE(reply);
    }
    *_reply = NULL;
    return rc;
}

inline static orte_grpcomm_signature_t *_extract_signature(opal_buffer_t *xfer)
{
    int rc;
    int32_t cnt;
    orte_grpcomm_signature_t *sig = NULL;
    /* setup a signature object */
    sig = OBJ_NEW(orte_grpcomm_signature_t);
    if( NULL == sig ){
        goto err_exit;
    }
    /* get the number of procs in this fence collective */
    cnt = 1;
    if (OPAL_SUCCESS != (rc = opal_dss.unpack(xfer, &sig->sz, &cnt, OPAL_SIZE))) {
        ORTE_ERROR_LOG(rc);
        goto err_exit;
    }
    /* if a signature was provided, get it */
    if (0 < sig->sz) {
        sig->signature = (orte_process_name_t*)malloc(sig->sz * sizeof(orte_process_name_t));
        cnt = sig->sz;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(xfer, sig->signature, &cnt, OPAL_UINT64))) {
            ORTE_ERROR_LOG(rc);
            goto err_exit;
        }
    }

    return sig;
err_exit:
    if( NULL != sig ){
        OBJ_RELEASE(sig);
    }
    return NULL;
}

inline static int _process_uri(opal_buffer_t *xfer)
{
    char *local_uri;
    int rc, cnt = 1;

    if (OPAL_SUCCESS != (rc = opal_dss.unpack(xfer, &local_uri, &cnt, OPAL_STRING))) {
        ORTE_ERROR_LOG(rc);
       return ORTE_ERROR;
    }

    /* if not NULL, then update our connection info as we might need
     * to send this proc a message at some point */
    if (NULL != local_uri) {
        // FIXME: Non-portable, move to the platform directory
        orte_rml.set_contact_info(local_uri);
        free(local_uri);
    }
    return ORTE_SUCCESS;
}

inline static int _process_kvps(pmix_server_pm_handler_t *pm, opal_buffer_t *xfer,
                                orte_grpcomm_signature_t *sig,
                                opal_buffer_t *blocal, opal_buffer_t *bremote, bool *_found)
{
    opal_buffer_t *bptr;
    opal_pmix_scope_t scope;
    opal_value_t kv;
    int handle;
    int rc, cnt = 1;
    bool found = false;

    OBJ_CONSTRUCT(blocal, opal_buffer_t);
    OBJ_CONSTRUCT(bremote, opal_buffer_t);
    while (OPAL_SUCCESS == (rc = opal_dss.unpack(xfer, &scope, &cnt, PMIX_SCOPE_T))) {
        found = true;  // at least one block of data is present
        /* unpack the buffer */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(xfer, &bptr, &cnt, OPAL_BUFFER))) {
            OPAL_ERROR_LOG(rc);
            goto err_cleanup;
        }
        /* prep the value_t */
        OBJ_CONSTRUCT(&kv, opal_value_t);
        kv.key = strdup("modex");
        kv.type = OPAL_BYTE_OBJECT;
        kv.data.bo.bytes = (uint8_t*)bptr->base_ptr;
        kv.data.bo.size = bptr->bytes_used;
        if (PMIX_LOCAL == scope) {
            /* store it in the local-modex dstore handle */
            opal_output_verbose(2, pmix_server_output,
                    "%s recvd LOCAL modex of size %d for proc %s",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                    (int)kv.data.bo.size, ORTE_NAME_PRINT(&pm->name));
            handle = pmix_server_local_handle;
            /* local procs will want this data */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(blocal, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                goto err_add_kv;
            }
        } else if (PMIX_REMOTE == scope) {
            /* store it in the remote-modex dstore handle */
            opal_output_verbose(2, pmix_server_output,
                    "%s recvd REMOTE modex of size %d for proc %s",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                    (int)kv.data.bo.size, ORTE_NAME_PRINT(&pm->name));
            handle = pmix_server_remote_handle;
            /* remote procs will want this data */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(bremote, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                goto err_add_kv;
            }
        } else {
            /* must be for global dissemination */
            opal_output_verbose(2, pmix_server_output,
                    "%s recvd GLOBAL modex of size %d for proc %s",
                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                    (int)kv.data.bo.size, ORTE_NAME_PRINT(&pm->name));
            handle = pmix_server_global_handle;
            /* local procs will want this data */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(blocal, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                goto err_add_kv;
            }
            /* remote procs will want this data */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(bremote, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                goto err_add_kv;
            }
        }
        if (OPAL_SUCCESS != (rc = opal_dstore.store(handle, (opal_identifier_t*)&pm->name, &kv))) {
            ORTE_ERROR_LOG(rc);
            goto err_add_kv;
        }
        bptr->base_ptr = NULL;  // protect the data region
        OBJ_RELEASE(bptr);
        OBJ_DESTRUCT(&kv);
        cnt = 1;
    }

    if (OPAL_ERR_UNPACK_READ_PAST_END_OF_BUFFER == rc) {
        rc = 0;
    }else{
        OPAL_ERROR_LOG(rc);
        goto err_cleanup;
    }

    *_found = found;
    return rc;

err_add_kv:
    OBJ_DESTRUCT(&kv);

err_cleanup:
    OBJ_DESTRUCT(blocal);
    OBJ_DESTRUCT(bremote);
    return rc;
}

/*
 * Dispatch to the appropriate action routine based on the state
 * of the connection with the peer.
 */
void pmix_server_process_peer(pmix_server_peer_t *peer)
{
    int rc, ret;
    int32_t cnt;
    pmix_cmd_t cmd;
    opal_buffer_t *reply = NULL;
    opal_buffer_t xfer, *bptr, buf, save, blocal, bremote;
    opal_value_t kv, *kp = &kv;
    opal_identifier_t id, idreq;
    orte_process_name_t name;
    pmix_server_pm_handler_t *pm;
    uint32_t tag;

    pmix_server_dmx_req_t *req, *nextreq;
    bool found;
    orte_grpcomm_signature_t *sig;

    /* xfer the message to a buffer for unpacking */
    OBJ_CONSTRUCT(&xfer, opal_buffer_t);
    opal_dss.load(&xfer, peer->recv_msg->data, peer->recv_msg->hdr.nbytes);
    tag = peer->recv_msg->hdr.tag;
    id = peer->recv_msg->hdr.id;
    peer->recv_msg->data = NULL;  // protect the transferred data
    OBJ_RELEASE(peer->recv_msg);

    /* retrieve the cmd */
    cnt = 1;
    if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &cmd, &cnt, PMIX_CMD_T))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&xfer);
        return;
    }
    opal_output_verbose(2, pmix_server_output,
                        "%s recvd pmix cmd %d from %s",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), cmd, ORTE_NAME_PRINT(&name));

    /* get the job and proc objects for the sender */
    memcpy((char*)&name, (char*)&id, sizeof(orte_process_name_t));
    if( NULL == (pm = pmix_server_handler_pm(name)) ){
        // FIXME: do we need to respond with reject to the sender?
        rc = ORTE_ERR_NOT_FOUND;
        ORTE_ERROR_LOG(rc);
        return;
    }

    switch(cmd) {
    case PMIX_FINALIZE_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd FINALIZE",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        pmix_server_finalize_pm(pm);
        reply = OBJ_NEW(opal_buffer_t);
        // FIXME: Do we need to pack the tag?
        goto reply_to_peer;
    case PMIX_ABORT_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd ABORT",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        /* unpack the status */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &ret, &cnt, OPAL_INT))) {
            ORTE_ERROR_LOG(rc);
            goto cleanup;
        }
        /* don't bother to unpack the message - we ignore this for now as the
         * proc should have emitted it for itself */
        pmix_server_abort_pm(pm, ret);

        reply = OBJ_NEW(opal_buffer_t);
        /* pack the tag */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &tag, 1, OPAL_UINT32))) {
            ORTE_ERROR_LOG(rc);
            goto cleanup;
        }
        goto reply_to_peer;
    case PMIX_FENCE_CMD:
    case PMIX_FENCENB_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd %s FROM PROC %s ON TAG %d",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                            (PMIX_FENCENB_CMD == cmd) ? "FENCE_NB" : "FENCE",
                            OPAL_NAME_PRINT(id), tag);

        if( NULL == (sig = _extract_signature(&xfer)) ){
            // TODO: In this case we need to reply with error!
            goto reply_fence;
        }

        if (4 < opal_output_get_verbosity(pmix_server_output)) {
            char *tmp=NULL;
            (void)opal_dss.print(&tmp, NULL, sig, ORTE_SIGNATURE);
            opal_output(0, "%s %s called with procs %s", ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                        (PMIX_FENCENB_CMD == cmd) ? "FENCE_NB" : "FENCE", tmp);
            free(tmp);
        }

        if( ORTE_SUCCESS != _process_uri(&xfer)){
            // TODO: In this case we need to reply with error!
            goto reply_fence;
        }

        if( ORTE_SUCCESS != _process_kvps(pm, &xfer, sig, &blocal, &bremote, &found) ){
            OBJ_RELEASE(sig);
            goto cleanup;
        }

        /* if we are in a group collective mode, then we need to prep
         * the data as it should be included in the modex */
        OBJ_CONSTRUCT(&save, opal_buffer_t);
        if (orte_process_info.num_procs < orte_direct_modex_cutoff) {
            /* need to include the id of the sender for later unpacking */
            opal_dss.pack(&save, &id, 1, OPAL_UINT64);
            opal_dss.copy_payload(&save, &xfer);
        }
        /* if data was given, unpack and store it in the pmix dstore - it is okay
         * if there was no data, it's just a fence */

        /* mark that we recvd data for this proc */
        ORTE_FLAG_SET(pm->proc, ORTE_PROC_FLAG_DATA_RECVD);
        /* see if anyone is waiting for it - we send a response even if no data
         * was actually provided so we don't hang if no modex data is being given */
        OPAL_LIST_FOREACH_SAFE(req, nextreq, &pmix_server_pending_dmx_reqs, pmix_server_dmx_req_t) {
            if (id == req->target) {
                /* yes - deliver a copy */
                reply = OBJ_NEW(opal_buffer_t);
                if (NULL == req->proxy) {
                    /* pack the status */
                    ret = OPAL_SUCCESS;
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
                        ORTE_ERROR_LOG(rc);
                        OBJ_RELEASE(reply);
                        return;
                    }
                    /* always pass the hostname */
                    OBJ_CONSTRUCT(&buf, opal_buffer_t);
                    OBJ_CONSTRUCT(&kv, opal_value_t);
                    kv.key = strdup(PMIX_HOSTNAME);
                    kv.type = OPAL_STRING;
                    kv.data.string = strdup(orte_process_info.nodename);
                    kp = &kv;
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(&buf, &kp, 1, OPAL_VALUE))) {
                        ORTE_ERROR_LOG(rc);
                        OBJ_RELEASE(reply);
                        OBJ_DESTRUCT(&buf);
                        OBJ_DESTRUCT(&kv);
                        return;
                    }
                    OBJ_DESTRUCT(&kv);
                    /* pack the hostname blob */
                    bptr = &buf;
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                        ORTE_ERROR_LOG(rc);
                        OBJ_DESTRUCT(&buf);
                        goto cleanup;
                    }
                    OBJ_DESTRUCT(&buf);
                    /* pass the local blob(s) */
                    opal_dss.copy_payload(reply, &blocal);
                    /* use the PMIX send to return the data */
                    PMIX_SERVER_QUEUE_SEND(req->peer, req->tag, reply);
                } else {
                    /* pack the id of the requested proc */
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &id, 1, OPAL_UINT64))) {
                        ORTE_ERROR_LOG(rc);
                        OBJ_RELEASE(sig);
                        goto cleanup;
                    }
                    /* pack the status */
                    ret = OPAL_SUCCESS;
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
                        ORTE_ERROR_LOG(rc);
                        goto cleanup;
                    }
                    /* always pass the hostname */
                    OBJ_CONSTRUCT(&buf, opal_buffer_t);
                    OBJ_CONSTRUCT(&kv, opal_value_t);
                    kv.key = strdup(PMIX_HOSTNAME);
                    kv.type = OPAL_STRING;
                    kv.data.string = strdup(orte_process_info.nodename);
                    kp = &kv;
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(&buf, &kp, 1, OPAL_VALUE))) {
                        OBJ_DESTRUCT(&buf);
                        OBJ_DESTRUCT(&kv);
                        ORTE_ERROR_LOG(rc);
                        goto cleanup;
                    }
                    OBJ_DESTRUCT(&kv);
                    /* pack the hostname blob */
                    bptr = &buf;
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                        ORTE_ERROR_LOG(rc);
                        OBJ_DESTRUCT(&buf);
                        goto cleanup;
                    }
                    OBJ_DESTRUCT(&buf);
                    /* pass the remote blob(s) */
                    opal_dss.copy_payload(reply, &bremote);
                    /* use RML to send the response */
                    orte_rml.send_buffer_nb(&req->proxy->name, reply,
                                            ORTE_RML_TAG_DIRECT_MODEX_RESP,
                                            orte_rml_send_callback, NULL);
                }
                opal_list_remove_item(&pmix_server_pending_dmx_reqs, &req->super);
                OBJ_RELEASE(req);
            }
        }
        OBJ_DESTRUCT(&blocal);
        OBJ_DESTRUCT(&bremote);

        /* send notification to myself */
        reply = OBJ_NEW(opal_buffer_t);
        /* pack the id of the sender */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &id, 1, OPAL_UINT64))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            OBJ_RELEASE(sig);
            goto reply_fence;
        }
        /* pack the socket of the sender */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &peer->sd, 1, OPAL_INT32))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            OBJ_RELEASE(sig);
            goto reply_fence;
        }
        /* pass the tag that this sender is sitting on */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &tag, 1, OPAL_UINT32))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            OBJ_RELEASE(sig);
            goto reply_fence;
        }
        /* pack the signature */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &sig, 1, ORTE_SIGNATURE))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            OBJ_RELEASE(sig);
            goto reply_fence;
        }
        OBJ_RELEASE(sig);
        /* include any data that is to be globally shared */
        if (found && 0 < save.bytes_used) {
            bptr = &save;
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                OBJ_RELEASE(reply);
                goto reply_fence;
            }
        }
        OBJ_DESTRUCT(&save);
        /* send it to myself for processing */
        orte_rml.send_buffer_nb(ORTE_PROC_MY_NAME, reply,
                                ORTE_RML_TAG_DAEMON_COLL,
                                orte_rml_send_callback, NULL);
        return;
    reply_fence:
        if (PMIX_FENCE_CMD == cmd) {
            /* send a release message back to the sender so they don't hang */
            reply = OBJ_NEW(opal_buffer_t);
            /* pack the tag */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &tag, 1, OPAL_UINT32))) {
                ORTE_ERROR_LOG(rc);
                goto cleanup;
            }
            goto reply_to_peer;
        }
        OBJ_DESTRUCT(&xfer);
        return;

    case PMIX_GET_CMD:
        /* unpack the id of the proc whose data is being requested */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &idreq, &cnt, OPAL_UINT64))) {
            ORTE_ERROR_LOG(rc);
            goto cleanup;
        }
        opal_output_verbose(2, pmix_server_output, "%s recvd GET FROM PROC %s FOR PROC %s",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), ORTE_NAME_PRINT(&name),
                            ORTE_NAME_PRINT((orte_process_name_t*)&idreq) );

        /* if we have not yet received data for this proc, then we just
         * need to track the request */
        if (!ORTE_FLAG_TEST(pm->proc, ORTE_PROC_FLAG_DATA_RECVD)) {
            if( (rc = _track_unknown_proc(pm, peer, idreq, tag, &reply)) ){
                ORTE_ERROR_LOG(rc);
                goto cleanup;
            }
            if( reply ){
                goto reply_to_peer;
            }
            /* nothing further to do as we are waiting for data */
            goto cleanup;
        }

        /* regardless of where this proc is located, we need to ensure
         * that the hostname it is on is *always* returned. Otherwise,
         * the non-blocking fence operation will cause us to fail if
         * the number of procs is below the cutoff as we will immediately
         * attempt to retrieve the hostname for each proc, but they may
         * not have posted their data by that time */
        if (ORTE_FLAG_TEST(pm->proc, ORTE_PROC_FLAG_LOCAL)) {
            rc = _reply_for_local_proc(pm, idreq, &reply);
        }else{
            rc = _reply_for_remote_proc(pm, idreq, &reply);
        }

        if( ORTE_SUCCESS != rc ){
            // In case of error we may steel want to notify the peer.
            if( NULL != reply ){
                goto reply_to_peer;
            }else{
                goto cleanup;
            }
        }
        goto reply_to_peer;
    case PMIX_GETATTR_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd GETATTR",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        /* create the attrs buffer */
        OBJ_CONSTRUCT(&buf, opal_buffer_t);

        // FIXME: Probably remote peer wants out answer anyway!
        //          We should pack ret in any case!
        /* stuff the values corresponding to the list of supported attrs */
        if (ORTE_SUCCESS != (ret = pmix_server_proc_info(&buf, pm))) {
            ORTE_ERROR_LOG(ret);
            goto cleanup;
        }
        /* return it */
        reply = OBJ_NEW(opal_buffer_t);
        /* pack the status */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
            ORTE_ERROR_LOG(rc);
            goto cleanup;
        }
        if (OPAL_SUCCESS == ret) {
            /* pack the buffer */
            bptr = &buf;
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                OBJ_DESTRUCT(&buf);
                goto cleanup;
            }
        }
        OBJ_DESTRUCT(&buf);
        goto reply_to_peer;
    default:
        ORTE_ERROR_LOG(ORTE_ERR_NOT_IMPLEMENTED);
        OBJ_DESTRUCT(&xfer);
        return;
    }

reply_to_peer:
    PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
    reply = NULL; // Drop it so it won't be released at cleanup
cleanup:
    if( NULL != reply ){
        OBJ_RELEASE(reply);
    }
    if( NULL != pm ){
        OBJ_RELEASE(pm);
    }
    OBJ_DESTRUCT(&xfer);

}
