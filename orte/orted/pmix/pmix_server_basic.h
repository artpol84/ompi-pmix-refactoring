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

#ifndef _PMIX_SERVER_BASIC_H_
#define _PMIX_SERVER_BASIC_H_

#include "orte_config.h"
#include "opal/class/opal_list.h"

BEGIN_C_DECLS

// ------------------------------------------------8<------------------------------------------------------//
// TODO: Schedule transaction to opal/mca/pmix/basic ?!

/* header for pmix client-server msgs - must
 * match that in opal/mca/pmix/native! */
typedef struct {
    opal_identifier_t id;
    uint8_t type;
    uint32_t tag;
    size_t nbytes;
} pmix_server_hdr_t;

// ------------------------------------------------8<------------------------------------------------------//

#define CLOSE_THE_SOCKET(socket)    \
    do {                            \
        shutdown(socket, 2);        \
        close(socket);              \
    } while(0)


typedef struct {
    opal_list_item_t super;
    uint32_t vpid;
    uint32_t cpu_bmp;
} pmix_local_peer_info_t;

typedef struct {
    bool hwloc_on;
    opal_buffer_t hwloc_topo;
    char* cpu_bmap;
    uint32_t jobid;
    uint32_t app_num;
    uint32_t usize;
    uint32_t size;
    uint32_t app_ldr;
    uint32_t rank;
    uint32_t glob_rank;
    uint32_t app_rank;
    uint32_t nproc_offs;
    uint32_t loc_rank;
    uint32_t loc_size;
    uint32_t node_rank;
    uint32_t node_size;
    uint32_t max_procs;
    opal_buffer_t *peers_cpu_bmaps;
    char *peers_list;
} pmix_job_info_t;

//

#define PMIX_KV_FIELD_uint32(x) (x->data.uint32)
#define PMIX_KV_FIELD_uint16(x) (x->data.uint16)
#define PMIX_KV_FIELD_string(x) (x->data.string)

#define PMIX_KV_TYPE_uint32 OPAL_UINT32
#define PMIX_KV_TYPE_uint16 OPAL_UINT16
#define PMIX_KV_TYPE_string OPAL_STRING

#define PMIX_ADD_KP_simple(_kp, _reply, _key, _field, _val, __eext )   \
{                                           \
    OBJ_CONSTRUCT(_kp, opal_value_t);       \
    _kp->key = strdup(_key);                \
    if( NULL == _kp->key ) {                \
        rc = ORTE_ERR_OUT_OF_RESOURCE;      \
        ORTE_ERROR_LOG(rc);                 \
        OBJ_DESTRUCT(kp);                   \
        goto __eext;                        \
    }                                       \
    _kp->type = PMIX_KV_TYPE_ ## _field;    \
    PMIX_KV_FIELD_ ## _field(_kp) = _val;   \
    if (OPAL_SUCCESS != (rc = opal_dss.pack(_reply, &_kp, 1, OPAL_VALUE))) {  \
        ORTE_ERROR_LOG(rc);                 \
        OBJ_DESTRUCT(kp);                   \
        free(_kp->key);                     \
        goto __eext;                        \
    }                                       \
    OBJ_DESTRUCT(kp);                       \
}

#define PMIX_ADD_KP_free_val(_kp, _reply, _key, _field, _val, __eext )   \
{                                           \
    OBJ_CONSTRUCT(_kp, opal_value_t);       \
    _kp->key = strdup(_key);                \
    if( NULL == _kp->key ) {                \
        rc = ORTE_ERR_OUT_OF_RESOURCE;      \
        ORTE_ERROR_LOG(rc);                 \
        OBJ_DESTRUCT(kp);                   \
        goto __eext;                        \
    }                                       \
    _kp->type = PMIX_KV_TYPE_ ## _field;    \
    PMIX_KV_FIELD_ ## _field(_kp) = _val;   \
    if (OPAL_SUCCESS != (rc = opal_dss.pack(_reply, &_kp, 1, OPAL_VALUE))) {  \
        ORTE_ERROR_LOG(rc);                 \
        OBJ_DESTRUCT(kp);                   \
        free(_kp->key);                     \
        free(_val);                         \
        goto __eext;                        \
    }                                       \
    OBJ_DESTRUCT(kp);                       \
}


#define PMIX_ADD_KP_uint32 PMIX_ADD_KP_simple
#define PMIX_ADD_KP_uint16 PMIX_ADD_KP_simple
#define PMIX_ADD_KP_string PMIX_ADD_KP_free_val

#define PMIX_ADD_KP(_kp, _reply, _key, _field, _val, __eext )   \
    PMIX_ADD_KP_ ## _field(_kp, _reply, _key, _field, _val, __eext)

END_C_DECLS

#endif /* _PMIX_SERVER_BASIC_H_ */
