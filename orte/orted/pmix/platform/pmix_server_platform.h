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

#ifndef _PMIX_SERVER_PLATFORM_H_
#define _PMIX_SERVER_PLATFORM_H_

#include "orte_config.h"
#include "orte/types.h"
#include "opal/types.h"
#include "orte/mca/state/state.h"
#include "orte/util/name_fns.h"
#include "orte/runtime/orte_globals.h"
#include "orte/orted/pmix/pmix_server_basic.h"
#include "pmix_server_platform.h"

BEGIN_C_DECLS

typedef struct {
    /** Parent object */
    opal_object_t super;

    orte_process_name_t name;
    orte_job_t *jdata;
    orte_proc_t *proc;
    orte_node_t *node;
    orte_app_context_t *app;
} pmix_server_pm_handler_t;
OBJ_CLASS_DECLARATION(pmix_server_pm_handler_t);

pmix_server_pm_handler_t *pmix_server_handler_pm(orte_process_name_t name);
int pmix_server_proc_info_pm(pmix_server_pm_handler_t *pm, pmix_job_info_t *jinfo);
void pmix_server_abort_pm(pmix_server_pm_handler_t *pm, int ret);
void pmix_server_finalize_pm(pmix_server_pm_handler_t *pm);

END_C_DECLS

#endif /* _PMIX_SERVER_PLATFORM_H_ */
