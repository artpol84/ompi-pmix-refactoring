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
#include "opal/util/output.h"
#include "opal/mca/dstore/dstore.h"
#include "orte/mca/state/state.h"
#include "orte/mca/errmgr/errmgr.h"
#include "orte/mca/grpcomm/grpcomm.h"
#include "orte/mca/rml/rml.h"
#include "orte/util/name_fns.h"
#include "orte/runtime/orte_globals.h"

#include "orte/orted/pmix/pmix_server_basic.h"
#include "pmix_server_platform.h"

static void pm_hndl_con(pmix_server_pm_handler_t *p)
{
    p->proc  = NULL;
    p->app   = NULL;
    p->jdata = NULL;
    p->node  = NULL;
}
static void pm_hndl_des(pmix_server_pm_handler_t *p)
{
}
OBJ_CLASS_INSTANCE(pmix_server_pm_handler_t,
                   opal_object_t,
                   pm_hndl_con, pm_hndl_des);

pmix_server_pm_handler_t *pmix_server_handler_pm(orte_process_name_t name)
{
    pmix_server_pm_handler_t *pm = OBJ_NEW(pmix_server_pm_handler_t);

    if (NULL == (pm->jdata = orte_get_job_data_object(name.jobid))) {
        OBJ_RELEASE(pm);
        return NULL;
    }

    if (NULL == (pm->proc = (orte_proc_t*)opal_pointer_array_get_item(pm->jdata->procs, name.vpid))) {
        OBJ_RELEASE(pm);
        return NULL;
    }

    /* convenience def */
    pm->node = pm->proc->node;
    pm->app = (orte_app_context_t*)opal_pointer_array_get_item(pm->jdata->apps, pm->proc->app_idx);

    return pm;
}

int pmix_server_proc_info_pm(pmix_server_pm_handler_t *pm, pmix_job_info_t *jinfo)
{
    orte_proc_t *pptr;
    int rc = 0;
    char *tmp;
    int i;

    /* mark the proc as having registered */
    ORTE_ACTIVATE_PROC_STATE(&pm->proc->name, ORTE_PROC_STATE_REGISTERED);

    jinfo->hwloc_on = false;
#if OPAL_HAVE_HWLOC
    /* pass the local topology for the app so it doesn't
     * have to discover it for itself */
    if (NULL != opal_hwloc_topology) {
        jinfo->hwloc_on = true;
        OBJ_CONSTRUCT(&jinfo->hwloc_topo, opal_buffer_t);
        if (OPAL_SUCCESS != (rc = opal_dss.pack(&jinfo->hwloc_topo, &opal_hwloc_topology, 1, OPAL_HWLOC_TOPO))) {
            ORTE_ERROR_LOG(rc);
            OBJ_DESTRUCT(&jinfo->hwloc_topo);
            return rc;
        }
    }
#endif /* OPAL_HAVE_HWLOC */

    /* cpuset */
    jinfo->cpu_bmap = NULL;
    if ( !orte_get_attribute(&pm->proc->attributes, ORTE_PROC_CPU_BITMAP, (void**)&jinfo->cpu_bmap, OPAL_STRING) ) {
        jinfo->cpu_bmap = NULL;
    }

    jinfo->jobid = pm->proc->name.jobid;
    jinfo->app_num = pm->proc->app_idx;
    jinfo->rank = pm->proc->name.vpid;
    jinfo->glob_rank = pm->proc->name.vpid + pm->jdata->offset;
    jinfo->app_rank = pm->proc->app_rank;
    jinfo->loc_rank = pm->proc->local_rank;
    jinfo->node_rank = pm->proc->node_rank;
    jinfo->nproc_offs = pm->jdata->offset;
    jinfo->usize = pm->jdata->num_procs;
    jinfo->size = pm->jdata->num_procs;
    jinfo->loc_size = pm->jdata->num_local_procs;
    jinfo->max_procs = pm->jdata->total_slots_alloc;
    jinfo->app_ldr = pm->app->first_rank;
    jinfo->node_size = pm->node->num_procs;

    /* construct the list of local peers */
    char **list = NULL;
    orte_process_name_t name;
    name.jobid = pm->jdata->jobid;
    name.vpid = 0;
    jinfo->peers_cpu_bmaps = OBJ_NEW(opal_buffer_t);
    for (i=0; i < pm->node->procs->size; i++) {
        if (NULL == (pptr = (orte_proc_t*)opal_pointer_array_get_item(pm->node->procs, i))) {
            continue;
        }
        if (pptr->name.jobid == pm->jdata->jobid) {
            opal_argv_append_nosize(&list, ORTE_VPID_PRINT(pptr->name.vpid));
            if (pptr->name.vpid < name.vpid) {
                name.vpid = pptr->name.vpid;
            }
            /* note that we have to pass the cpuset for each local
             * peer so locality can be computed */
            tmp = NULL;
            if (orte_get_attribute(&pptr->attributes, ORTE_PROC_CPU_BITMAP, (void**)&tmp, OPAL_STRING)) {
                /* add the name of the proc */
                rc = opal_dss.pack(jinfo->peers_cpu_bmaps, (opal_identifier_t*)&pptr->name, 1, OPAL_UINT64);
                if ( OPAL_SUCCESS != rc ) {
                    ORTE_ERROR_LOG(rc);
                    opal_argv_free(list);
                    return rc;
                }
                /* add its cpuset */
                if (OPAL_SUCCESS != (rc = opal_dss.pack(jinfo->peers_cpu_bmaps, &tmp, 1, OPAL_STRING))) {
                    ORTE_ERROR_LOG(rc);
                    opal_argv_free(list);
                    return rc;
                }
            }
        }
    }

    tmp = opal_argv_join(list, ',');
    opal_argv_free(list);
    jinfo->peers_list = tmp;

    return ORTE_SUCCESS;
}

void pmix_server_abort_pm(pmix_server_pm_handler_t *pm, int ret)
{
    pm->proc->exit_code = ret;
    /* we will let the ODLS report this to errmgr when the proc exits, so
     * send the release so the proc can depart */
    ORTE_FLAG_SET(pm->proc, ORTE_PROC_FLAG_ABORT);
    ORTE_UPDATE_EXIT_STATUS(ret);
}

void pmix_server_finalize_pm(pmix_server_pm_handler_t *pm)
{
    /* mark the proc as having deregistered */
    ORTE_FLAG_SET(pm->proc, ORTE_PROC_FLAG_HAS_DEREG);
}
