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
//#include "pmix_server.h"
#include "pmix_server_internal.h"




/* stuff proc attributes for sending back to a proc */
int stuff_proc_values(opal_buffer_t *reply, orte_job_t *jdata, orte_proc_t *proc)
{
    char *tmp;
    opal_value_t kv, *kp;
    int rc;
    orte_node_t *node;
    orte_app_context_t *app;
    orte_proc_t *pptr;
    int i;
    char **list;
    orte_process_name_t name;
    opal_buffer_t buf;

    /* convenience def */
    node = proc->node;
    app = (orte_app_context_t*)opal_pointer_array_get_item(jdata->apps, proc->app_idx);
    kp = &kv;

#if OPAL_HAVE_HWLOC
    /* pass the local topology for the app so it doesn't
     * have to discover it for itself */
    if (NULL != opal_hwloc_topology) {
        OBJ_CONSTRUCT(&buf, opal_buffer_t);
        if (OPAL_SUCCESS != (rc = opal_dss.pack(&buf, &opal_hwloc_topology, 1, OPAL_HWLOC_TOPO))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&buf);
            return rc;
        }
        OBJ_CONSTRUCT(&kv, opal_value_t);
        kv.key = strdup(PMIX_LOCAL_TOPO);
        kv.type = OPAL_BYTE_OBJECT;
        opal_dss.unload(&buf, (void**)&kv.data.bo.bytes, &kv.data.bo.size);
        OBJ_DESTRUCT(&buf);
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&kv);
            return rc;
        }
        OBJ_DESTRUCT(&kv);
    }
#endif /* OPAL_HAVE_HWLOC */
    /* cpuset */
    tmp = NULL;
    if (orte_get_attribute(&proc->attributes, ORTE_PROC_CPU_BITMAP, (void**)&tmp, OPAL_STRING)) {
        OBJ_CONSTRUCT(&kv, opal_value_t);
        kv.key = strdup(PMIX_CPUSET);
        kv.type = OPAL_STRING;
        kv.data.string = tmp;
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&kv);
            return rc;
        }
        OBJ_DESTRUCT(&kv);
    }
    /* jobid */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_JOBID);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = proc->name.jobid;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* appnum */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_APPNUM);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = proc->app_idx;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* rank */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_RANK);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = proc->name.vpid;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* global rank */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_GLOBAL_RANK);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = proc->name.vpid + jdata->offset;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* app rank */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_APP_RANK);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = proc->app_rank;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* offset */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_NPROC_OFFSET);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = jdata->offset;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* local rank */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_LOCAL_RANK);
    kv.type = OPAL_UINT16;
    kv.data.uint16 = proc->local_rank;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* node rank */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_NODE_RANK);
    kv.type = OPAL_UINT16;
    kv.data.uint16 = proc->node_rank;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* construct the list of local peers */
    list = NULL;
    name.jobid = jdata->jobid;
    name.vpid = 0;
    OBJ_CONSTRUCT(&buf, opal_buffer_t);
    for (i=0; i < node->procs->size; i++) {
        if (NULL == (pptr = (orte_proc_t*)opal_pointer_array_get_item(node->procs, i))) {
            continue;
        }
        if (pptr->name.jobid == jdata->jobid) {
            opal_argv_append_nosize(&list, ORTE_VPID_PRINT(pptr->name.vpid));
            if (pptr->name.vpid < name.vpid) {
                name.vpid = pptr->name.vpid;
            }
            /* note that we have to pass the cpuset for each local
             * peer so locality can be computed */
            tmp = NULL;
            if (orte_get_attribute(&pptr->attributes, ORTE_PROC_CPU_BITMAP, (void**)&tmp, OPAL_STRING)) {
                /* add the name of the proc */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(&buf, (opal_identifier_t*)&pptr->name, 1, OPAL_UINT64))) {
                    ORTE_ERROR_LOG(rc);
                    opal_argv_free(list);
                    return rc;
                }
                /* add its cpuset */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(&buf, &tmp, 1, OPAL_STRING))) {
                    ORTE_ERROR_LOG(rc);
                    opal_argv_free(list);
                    return rc;
                }
            }
        }
    }
    /* pass the blob containing the cpusets for all local peers - note
     * that the cpuset of the proc we are responding to will be included,
     * so we don't need to send it separately */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_LOCAL_CPUSETS);
    kv.type = OPAL_BYTE_OBJECT;
    opal_dss.unload(&buf, (void**)&kv.data.bo.bytes, &kv.data.bo.size);
    OBJ_DESTRUCT(&buf);
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        opal_argv_free(list);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* construct the list of peers for transmission */
    tmp = opal_argv_join(list, ',');
    opal_argv_free(list);
    /* pass the local ldr */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_LOCALLDR);
    kv.type = OPAL_UINT64;
    kv.data.uint64 = *(uint64_t*)&name;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        free(tmp);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* pass the list of peers */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_LOCAL_PEERS);
    kv.type = OPAL_STRING;
    kv.data.string = tmp;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* app ldr */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_APPLDR);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = app->first_rank;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* univ size */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_UNIV_SIZE);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = jdata->num_procs;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* job size */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_JOB_SIZE);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = jdata->num_procs;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* local size */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_LOCAL_SIZE);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = jdata->num_local_procs;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* node size */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_NODE_SIZE);
    kv.type = OPAL_UINT32;
    kv.data.uint32 = node->num_procs;
    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &kp, 1, OPAL_VALUE))) {
        ORTE_ERROR_LOG(rc);
        OBJ_DESTRUCT(&kv);
        return rc;
    }
    OBJ_DESTRUCT(&kv);
    /* max procs */
    OBJ_CONSTRUCT(&kv, opal_value_t);
    kv.key = strdup(PMIX_MAX_PROCS);
    kv.type = OPAL_UINT32;
    kv.data.uint16 = jdata->total_slots_alloc;
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
    opal_buffer_t *reply, xfer, *bptr, buf, save, blocal, bremote;
    opal_value_t kv, *kvp, *kvp2, *kp;
    opal_identifier_t id, idreq;
    orte_process_name_t name;
    orte_job_t *jdata;
    orte_proc_t *proc;
    opal_list_t values;
    uint32_t tag;
    opal_pmix_scope_t scope;
    int handle;
    pmix_server_dmx_req_t *req, *nextreq;
    bool found;
    orte_grpcomm_signature_t *sig;
    char *local_uri;

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
                        "%s recvd pmix cmd %d",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME), cmd);
    switch(cmd) {
    case PMIX_ABORT_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd ABORT",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        /* unpack the status */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &ret, &cnt, OPAL_INT))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* don't bother to unpack the message - we ignore this for now as the
         * proc should have emitted it for itself */
        memcpy(&name, &id, sizeof(orte_process_name_t));
        /* go find the proc structure for this process */
        if (NULL == (jdata = orte_get_job_data_object(name.jobid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
        } else {
            if (NULL == (proc = (orte_proc_t*)opal_pointer_array_get_item(jdata->procs, name.vpid))) {
                ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            } else {
                proc->exit_code = ret;
                ORTE_FLAG_SET(proc, ORTE_PROC_FLAG_ABORT);
                ORTE_UPDATE_EXIT_STATUS(ret);
            }
        }
        /* we will let the ODLS report this to errmgr when the proc exits, so
         * send the release so the proc can depart */
        reply = OBJ_NEW(opal_buffer_t);
        /* pack the tag */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &tag, 1, OPAL_UINT32))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
        OBJ_DESTRUCT(&xfer);
        return;
    case PMIX_FENCE_CMD:
    case PMIX_FENCENB_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd %s FROM PROC %s ON TAG %d",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                            (PMIX_FENCENB_CMD == cmd) ? "FENCE_NB" : "FENCE",
                            OPAL_NAME_PRINT(id), tag);
        /* get the job and proc objects for the sender */
        memcpy((char*)&name, (char*)&id, sizeof(orte_process_name_t));
        if (NULL == (jdata = orte_get_job_data_object(name.jobid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        if (NULL == (proc = (orte_proc_t*)opal_pointer_array_get_item(jdata->procs, name.vpid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* setup a signature object */
        sig = OBJ_NEW(orte_grpcomm_signature_t);
        /* get the number of procs in this fence collective */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &sig->sz, &cnt, OPAL_SIZE))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(sig);
            goto reply_fence;
        }
        /* if a signature was provided, get it */
        if (0 < sig->sz) {
            sig->signature = (orte_process_name_t*)malloc(sig->sz * sizeof(orte_process_name_t));
            cnt = sig->sz;
            if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, sig->signature, &cnt, OPAL_UINT64))) {
                ORTE_ERROR_LOG(rc);
                OBJ_RELEASE(sig);
                goto reply_fence;
            }
        }
        if (4 < opal_output_get_verbosity(pmix_server_output)) {
            char *tmp=NULL;
            (void)opal_dss.print(&tmp, NULL, sig, ORTE_SIGNATURE);
            opal_output(0, "%s %s called with procs %s",
                        ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                        (PMIX_FENCENB_CMD == cmd) ? "FENCE_NB" : "FENCE", tmp);
            free(tmp);
        }
        /* get the URI for this process */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &local_uri, &cnt, OPAL_STRING))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(sig);
            goto reply_fence;
        }
        /* if not NULL, then update our connection info as we might need
         * to send this proc a message at some point */
        if (NULL != local_uri) {
            orte_rml.set_contact_info(local_uri);
            free(local_uri);
        }
        /* if we are in a group collective mode, then we need to prep
         * the data as it should be included in the modex */
        OBJ_CONSTRUCT(&save, opal_buffer_t);
        if (orte_process_info.num_procs < orte_full_modex_cutoff) {
            /* need to include the id of the sender for later unpacking */
            opal_dss.pack(&save, &id, 1, OPAL_UINT64);
            opal_dss.copy_payload(&save, &xfer);
        }
        /* if data was given, unpack and store it in the pmix dstore - it is okay
         * if there was no data, it's just a fence */
        cnt = 1;
        found = false;
        OBJ_CONSTRUCT(&blocal, opal_buffer_t);
        OBJ_CONSTRUCT(&bremote, opal_buffer_t);
        while (OPAL_SUCCESS == (rc = opal_dss.unpack(&xfer, &scope, &cnt, PMIX_SCOPE_T))) {
            found = true;  // at least one block of data is present
            /* unpack the buffer */
            cnt = 1;
            if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &bptr, &cnt, OPAL_BUFFER))) {
                OPAL_ERROR_LOG(rc);
                OBJ_DESTRUCT(&xfer);
                OBJ_RELEASE(sig);
                return;
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
                                    (int)kv.data.bo.size,
                                    ORTE_NAME_PRINT(&peer->name));
                handle = pmix_server_local_handle;
                /* local procs will want this data */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(&blocal, &bptr, 1, OPAL_BUFFER))) {
                    ORTE_ERROR_LOG(rc);
                    OBJ_DESTRUCT(&xfer);
                    OBJ_RELEASE(sig);
                    OBJ_DESTRUCT(&blocal);
                    OBJ_DESTRUCT(&bremote);
                    return;
                }
            } else if (PMIX_REMOTE == scope) {
                /* store it in the remote-modex dstore handle */
                opal_output_verbose(2, pmix_server_output,
                                    "%s recvd REMOTE modex of size %d for proc %s",
                                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                                    (int)kv.data.bo.size,
                                    ORTE_NAME_PRINT(&peer->name));
                handle = pmix_server_remote_handle;
                /* remote procs will want this data */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(&bremote, &bptr, 1, OPAL_BUFFER))) {
                    ORTE_ERROR_LOG(rc);
                    OBJ_DESTRUCT(&xfer);
                    OBJ_RELEASE(sig);
                    OBJ_DESTRUCT(&blocal);
                    OBJ_DESTRUCT(&bremote);
                    return;
                }
            } else {
                /* must be for global dissemination */
                opal_output_verbose(2, pmix_server_output,
                                    "%s recvd GLOBAL modex of size %d for proc %s",
                                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                                    (int)kv.data.bo.size,
                                    ORTE_NAME_PRINT(&peer->name));
                handle = pmix_server_global_handle;
                /* local procs will want this data */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(&blocal, &bptr, 1, OPAL_BUFFER))) {
                    ORTE_ERROR_LOG(rc);
                    OBJ_DESTRUCT(&xfer);
                    OBJ_RELEASE(sig);
                    OBJ_DESTRUCT(&blocal);
                    OBJ_DESTRUCT(&bremote);
                    return;
                }
                /* remote procs will want this data */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(&bremote, &bptr, 1, OPAL_BUFFER))) {
                    ORTE_ERROR_LOG(rc);
                    OBJ_DESTRUCT(&xfer);
                    OBJ_RELEASE(sig);
                    OBJ_DESTRUCT(&blocal);
                    OBJ_DESTRUCT(&bremote);
                    return;
                }
            }
            if (OPAL_SUCCESS != (rc = opal_dstore.store(handle, &id, &kv))) {
                ORTE_ERROR_LOG(rc);
                OBJ_DESTRUCT(&kv);
                OBJ_DESTRUCT(&xfer);
                OBJ_RELEASE(sig);
                return;
            }
            bptr->base_ptr = NULL;  // protect the data region
            OBJ_RELEASE(bptr);
            OBJ_DESTRUCT(&kv);
            cnt = 1;
        }
        if (OPAL_ERR_UNPACK_READ_PAST_END_OF_BUFFER != rc) {
            OPAL_ERROR_LOG(rc);
        }
        /* mark that we recvd data for this proc */
        ORTE_FLAG_SET(proc, ORTE_PROC_FLAG_DATA_RECVD);
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
                        OBJ_RELEASE(reply);
                        OBJ_DESTRUCT(&xfer);
                        OBJ_DESTRUCT(&buf);
                        return;
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
                        OBJ_RELEASE(reply);
                        OBJ_DESTRUCT(&xfer);
                        OBJ_RELEASE(sig);
                        return;
                    }
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
                        OBJ_RELEASE(reply);
                        OBJ_DESTRUCT(&xfer);
                        OBJ_DESTRUCT(&buf);
                        return;
                    }
                    OBJ_DESTRUCT(&buf);
                    /* pass the remote blob(s) */
                    opal_dss.copy_payload(reply, &bremote);
                    /* use RML to send the response */
                    orte_rml.send_buffer_nb(&req->proxy->name, reply,
                                            ORTE_RML_TAG_DIRECT_MODEX_RESP,
                                            orte_rml_send_callback, NULL);
                }
            }
            opal_list_remove_item(&pmix_server_pending_dmx_reqs, &req->super);
            OBJ_RELEASE(req);
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
                OBJ_RELEASE(reply);
                OBJ_DESTRUCT(&xfer);
                return;
            }
            PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
        }
        OBJ_DESTRUCT(&xfer);
        return;

    case PMIX_GET_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd GET",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        /* unpack the id of the proc whose data is being requested */
        cnt = 1;
        if (OPAL_SUCCESS != (rc = opal_dss.unpack(&xfer, &idreq, &cnt, OPAL_UINT64))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* lookup the proc object */
        memcpy((char*)&name, (char*)&idreq, sizeof(orte_process_name_t));
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd GET FROM PROC %s FOR PROC %s",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                            ORTE_NAME_PRINT((orte_process_name_t*)&id),
                            ORTE_NAME_PRINT(&name));
        if (NULL == (jdata = orte_get_job_data_object(name.jobid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        if (NULL == (proc = (orte_proc_t*)opal_pointer_array_get_item(jdata->procs, name.vpid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* if we have not yet received data for this proc, then we just
         * need to track the request */
        if (!ORTE_FLAG_TEST(proc, ORTE_PROC_FLAG_DATA_RECVD)) {
            /* are we already tracking it? */
            found = false;
            OPAL_LIST_FOREACH(req, &pmix_server_pending_dmx_reqs, pmix_server_dmx_req_t) {
                if (idreq == req->target) {
                    /* yes, so we don't need to send another request, but
                     * we do need to track that this peer also wants
                     * a copy */
                    found = true;
                    break;
                }
            }
            /* track the request */
            req = OBJ_NEW(pmix_server_dmx_req_t);
            OBJ_RETAIN(peer);  // just to be safe
            req->peer = peer;
            req->target = idreq;
            req->tag = tag;
            opal_list_append(&pmix_server_pending_dmx_reqs, &req->super);
            if (!found) {
                /* this is a new tracker - see if we need to se nd a data
                 * request to some remote daemon to resolve it */
                if (!ORTE_FLAG_TEST(proc, ORTE_PROC_FLAG_LOCAL)) {
                    /* nope - who is hosting this proc */
                    if (NULL == proc->node || NULL == proc->node->daemon) {
                        /* we are hosed - pack an error and return it */
                        reply = OBJ_NEW(opal_buffer_t);
                        ret = ORTE_ERR_NOT_FOUND;
                        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
                            ORTE_ERROR_LOG(rc);
                            OBJ_RELEASE(reply);
                            return;
                        }
                        PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
                        return;
                    }
                    /* setup the request */
                    reply = OBJ_NEW(opal_buffer_t);
                    /* pack the proc we want info about */
                    if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &idreq, 1, OPAL_UINT64))) {
                        ORTE_ERROR_LOG(rc);
                        return;
                    }
                    /* spmix_server_start_listeningend the request - the recv will come back elsewhere
                     * and reply to the original requestor */
                    orte_rml.send_buffer_nb(&proc->node->daemon->name, reply,
                                            ORTE_RML_TAG_DIRECT_MODEX,
                                            orte_rml_send_callback, NULL);
                }
            }
            /* nothing further to do as we are waiting for data */
            return;
        }

        /* regardless of where this proc is located, we need to ensure
         * that the hostname it is on is *always* returned. Otherwise,
         * the non-blocking fence operation will cause us to fail if
         * the number of procs is below the cutoff as we will immediately
         * attempt to retrieve the hostname for each proc, but they may
         * not have posted their data by that time */
        if (ORTE_FLAG_TEST(proc, ORTE_PROC_FLAG_LOCAL)) {
            opal_output_verbose(2, pmix_server_output,
                                "%s recvd GET PROC %s IS LOCAL",
                                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                                ORTE_NAME_PRINT(&name));
            kvp = NULL;
            kvp2 = NULL;
            /* retrieve the local blob for that proc */
            OBJ_CONSTRUCT(&values, opal_list_t);
            if (OPAL_SUCCESS == (ret = opal_dstore.fetch(pmix_server_local_handle, &idreq, "modex", &values))) {
                kvp = (opal_value_t*)opal_list_remove_first(&values);
            }
            OPAL_LIST_DESTRUCT(&values);
            /* retrieve the global blob for that proc */
            OBJ_CONSTRUCT(&values, opal_list_t);
            if (OPAL_SUCCESS == (ret = opal_dstore.fetch(pmix_server_global_handle, &idreq, "modex", &values))) {
                kvp2 = (opal_value_t*)opal_list_remove_first(&values);
            }
            OPAL_LIST_DESTRUCT(&values);
            /* return it */
            reply = OBJ_NEW(opal_buffer_t);
            /* pack the status */
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
                ORTE_ERROR_LOG(rc);
                OBJ_RELEASE(reply);
                OBJ_DESTRUCT(&xfer);
                return;
            }
            /* pass the hostname */
            OBJ_CONSTRUCT(&buf, opal_buffer_t);
            OBJ_CONSTRUCT(&kv, opal_value_t);
            kv.key = strdup(PMIX_HOSTNAME);
            kv.type = OPAL_STRING;
            kv.data.string = strdup(orte_process_info.nodename);
            kp = &kv;
            if (OPAL_SUCCESS != (rc = opal_dss.pack(&buf, &kp, 1, OPAL_VALUE))) {
                ORTE_ERROR_LOG(rc);
                OBJ_RELEASE(reply);
                OBJ_DESTRUCT(&xfer);
                OBJ_DESTRUCT(&buf);
                OBJ_DESTRUCT(&kv);
                return;
            }
            OBJ_DESTRUCT(&kv);
            /* pack the blob */
            bptr = &buf;
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                OBJ_RELEASE(reply);
                OBJ_DESTRUCT(&xfer);
                OBJ_DESTRUCT(&buf);
                return;
            }
            OBJ_DESTRUCT(&buf);
            /* local blob */
            if (NULL != kvp) {
                opal_output_verbose(2, pmix_server_output,
                                    "%s passing local blob of size %d from proc %s to proc %s",
                                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                                    (int)kvp->data.bo.size,
                                    ORTE_NAME_PRINT(&name),
                                    ORTE_NAME_PRINT(&peer->name));
                OBJ_CONSTRUCT(&buf, opal_buffer_t);
                opal_dss.load(&buf, kvp->data.bo.bytes, kvp->data.bo.size);
                /* protect the data */
                kvp->data.bo.bytes = NULL;
                kvp->data.bo.size = 0;
                bptr = &buf;
                if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                    ORTE_ERROR_LOG(rc);
                    OBJ_RELEASE(reply);
                    OBJ_DESTRUCT(&xfer);
                    OBJ_DESTRUCT(&buf);
                    return;
                }
                OBJ_DESTRUCT(&buf);
                OBJ_RELEASE(kvp);
            }
            /* global blob */
            if (NULL != kvp2) {
                opal_output_verbose(2, pmix_server_output,
                                    "%s passing global blob of size %d from proc %s to proc %s",
                                    ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                                    (int)kvp2->data.bo.size,
                                    ORTE_NAME_PRINT(&name),
                                    ORTE_NAME_PRINT(&peer->name));
                OBJ_CONSTRUCT(&buf, opal_buffer_t);
                opal_dss.load(&buf, kvp2->data.bo.bytes, kvp2->data.bo.size);
                /* protect the data */
                kvp2->data.bo.bytes = NULL;
                kvp2->data.bo.size = 0;
                bptr = &buf;
                if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                    ORTE_ERROR_LOG(rc);
                    OBJ_RELEASE(reply);
                    OBJ_DESTRUCT(&xfer);
                    OBJ_DESTRUCT(&buf);
                    return;
                }
                OBJ_DESTRUCT(&buf);
                OBJ_RELEASE(kvp2);
            }
            PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
            OBJ_DESTRUCT(&xfer);
            return;
        }

        opal_output_verbose(2, pmix_server_output,
                            "%s recvd GET PROC %s IS NON-LOCAL",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                            ORTE_NAME_PRINT(&name));
        OBJ_DESTRUCT(&xfer);  // done with this
        /* since we already have this proc's data, we know that the
         * entire blob is stored in the remote handle - so get it */
        OBJ_CONSTRUCT(&values, opal_list_t);
        if (OPAL_SUCCESS == (ret = opal_dstore.fetch(pmix_server_remote_handle, &idreq, "modex", &values))) {
            kvp = (opal_value_t*)opal_list_remove_first(&values);
            OPAL_LIST_DESTRUCT(&values);
            opal_output_verbose(2, pmix_server_output,
                                "%s passing blob of size %d from remote proc %s to proc %s",
                                ORTE_NAME_PRINT(ORTE_PROC_MY_NAME),
                                (int)kvp->data.bo.size,
                                ORTE_NAME_PRINT(&name),
                                ORTE_NAME_PRINT(&peer->name));
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
                OBJ_RELEASE(reply);
                OBJ_DESTRUCT(&buf);
                return;
            }
            /* xfer the data - the blobs are in the buffer,
             * so don't repack them. They will include the remote
             * hostname, so don't add it again */
            opal_dss.copy_payload(reply, &buf);
            OBJ_DESTRUCT(&buf);
            PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
            return;
        }
        OPAL_LIST_DESTRUCT(&values);
        /* if we get here, then the data should have been there, but wasn't found
         * for some bizarre reason - pass back an error to ensure we don't block */
        reply = OBJ_NEW(opal_buffer_t);
        /* pack the error status */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            return;
        }
        PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
        return;

    case PMIX_GETATTR_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd GETATTR",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        /* create the attrs buffer */
        OBJ_CONSTRUCT(&buf, opal_buffer_t);
        /* look up this proc */
        memcpy((char*)&name, (char*)&id, sizeof(orte_process_name_t));
        if (NULL == (jdata = orte_get_job_data_object(name.jobid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&buf);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        if (NULL == (proc = (orte_proc_t*)opal_pointer_array_get_item(jdata->procs, name.vpid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&buf);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* mark the proc as having registered */
        ORTE_ACTIVATE_PROC_STATE(&proc->name, ORTE_PROC_STATE_REGISTERED);
        /* stuff the values corresponding to the list of supported attrs */
        if (ORTE_SUCCESS != (ret = stuff_proc_values(&buf, jdata, proc))) {
            ORTE_ERROR_LOG(ret);
            OBJ_DESTRUCT(&buf);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* return it */
        reply = OBJ_NEW(opal_buffer_t);
        /* pack the status */
        if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &ret, 1, OPAL_INT))) {
            ORTE_ERROR_LOG(rc);
            OBJ_RELEASE(reply);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        if (OPAL_SUCCESS == ret) {
            /* pack the buffer */
            bptr = &buf;
            if (OPAL_SUCCESS != (rc = opal_dss.pack(reply, &bptr, 1, OPAL_BUFFER))) {
                ORTE_ERROR_LOG(rc);
                OBJ_RELEASE(reply);
                OBJ_DESTRUCT(&xfer);
                OBJ_DESTRUCT(&buf);
                return;
            }
        }
        OBJ_DESTRUCT(&buf);
        PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
        OBJ_DESTRUCT(&xfer);
        return;

    case PMIX_FINALIZE_CMD:
        opal_output_verbose(2, pmix_server_output,
                            "%s recvd FINALIZE",
                            ORTE_NAME_PRINT(ORTE_PROC_MY_NAME));
        /* look up this proc */
        memcpy((char*)&name, (char*)&id, sizeof(orte_process_name_t));
        if (NULL == (jdata = orte_get_job_data_object(name.jobid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&buf);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        if (NULL == (proc = (orte_proc_t*)opal_pointer_array_get_item(jdata->procs, name.vpid))) {
            ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
            OBJ_DESTRUCT(&buf);
            OBJ_DESTRUCT(&xfer);
            return;
        }
        /* mark the proc as having deregistered */
        ORTE_FLAG_SET(proc, ORTE_PROC_FLAG_HAS_DEREG);
        /* send the release */
        reply = OBJ_NEW(opal_buffer_t);
        PMIX_SERVER_QUEUE_SEND(peer, tag, reply);
        OBJ_DESTRUCT(&xfer);
        break;

    default:
        ORTE_ERROR_LOG(ORTE_ERR_NOT_IMPLEMENTED);
        OBJ_DESTRUCT(&xfer);
        return;
    }
}
