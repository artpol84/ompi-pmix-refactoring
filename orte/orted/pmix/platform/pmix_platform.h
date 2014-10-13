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

#ifndef PMIX_PLATFORM_H
#define PMIX_PLATFORM_H

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

//#include "opal_stdint.h"
//#include "opal/class/opal_list.h"
//#include "opal/mca/base/mca_base_var.h"
//#include "opal/util/opal_environ.h"
//#include "opal/util/show_help.h"
//#include "opal/util/output.h"
//#include "opal/opal_socket_errno.h"
//#include "opal/util/if.h"
//#include "opal/util/net.h"
//#include "opal/util/argv.h"
//#include "opal/mca/dstore/dstore.h"

#include "orte/mca/state/state.h"
//#include "orte/mca/errmgr/errmgr.h"
//#include "orte/mca/grpcomm/grpcomm.h"
//#include "orte/mca/rml/rml.h"
#include "orte/util/name_fns.h"
#include "orte/runtime/orte_globals.h"

#include "orte/orted/pmix/pmix_basic.h"
#include "pmix_platform.h"

typedef struct {
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

#endif // PMIX_PLATFORM_H
