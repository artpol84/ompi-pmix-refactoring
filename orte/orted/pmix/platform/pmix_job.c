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

#include "orte/orted/pmix/pmix_basic.h"
#include "pmix_platform.h"

int pmix_server_proc_info_pm(orte_process_name_t name, pmix_job_info_t *jinfo)
{
    orte_job_t *jdata;
    orte_proc_t *proc;
    orte_node_t *node = NULL;
    orte_app_context_t *app;
    orte_proc_t *pptr;
    int rc = 0;
    char *tmp;
    int i;

    if (NULL == (jdata = orte_get_job_data_object(name.jobid))) {
        ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
        return ORTE_ERR_NOT_FOUND;
    }

    if (NULL == (proc = (orte_proc_t*)opal_pointer_array_get_item(jdata->procs, name.vpid))) {
        ORTE_ERROR_LOG(ORTE_ERR_NOT_FOUND);
        return ORTE_ERR_NOT_FOUND;
    }

    /* mark the proc as having registered */
    ORTE_ACTIVATE_PROC_STATE(&proc->name, ORTE_PROC_STATE_REGISTERED);

    /* convenience def */
    node = proc->node;
    app = (orte_app_context_t*)opal_pointer_array_get_item(jdata->apps, proc->app_idx);

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
    if ( !orte_get_attribute(&proc->attributes, ORTE_PROC_CPU_BITMAP, (void**)&jinfo->cpu_bmap, OPAL_STRING) ) {
        jinfo->cpu_bmap = NULL;
    }

    jinfo->jobid = proc->name.jobid;
    jinfo->app_num = proc->app_idx;
    jinfo->rank = proc->name.vpid;
    jinfo->glob_rank = proc->name.vpid + jdata->offset;
    jinfo->app_rank = proc->app_rank;
    jinfo->loc_rank = proc->local_rank;
    jinfo->node_rank = proc->node_rank;
    jinfo->nproc_offs = jdata->offset;
    jinfo->usize = jdata->num_procs;
    jinfo->size = jdata->num_procs;
    jinfo->loc_size = jdata->num_local_procs;
    jinfo->max_procs = jdata->total_slots_alloc;
    jinfo->app_ldr = app->first_rank;
    jinfo->node_size = node->num_procs;

    /* construct the list of local peers */
    char **list = NULL;
    name.jobid = jdata->jobid;
    name.vpid = 0;
    jinfo->peers_cpu_bmaps = OBJ_NEW(opal_buffer_t);
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
