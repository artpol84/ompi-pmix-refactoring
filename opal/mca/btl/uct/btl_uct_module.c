/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2004-2007 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2013 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2014-2018 Los Alamos National Security, LLC. All rights
 *                         reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "opal_config.h"
#include <string.h>
#include "opal/class/opal_bitmap.h"
#include "opal/mca/btl/btl.h"
#include "opal/datatype/opal_convertor.h"
#include "opal/mca/mpool/base/base.h"
#include "opal/mca/mpool/mpool.h"

#include "btl_uct.h"
#include "btl_uct_endpoint.h"

static int mca_btl_uct_reg_mem (void *reg_data, void *base, size_t size, mca_rcache_base_registration_t *reg);
static int mca_btl_uct_dereg_mem (void *reg_data, mca_rcache_base_registration_t *reg);

static int mca_btl_uct_add_procs (mca_btl_base_module_t *btl,
                                  size_t nprocs, opal_proc_t **opal_procs,
                                  mca_btl_base_endpoint_t **peers,
                                  opal_bitmap_t *reachable)
{
    mca_btl_uct_module_t *uct_btl = (mca_btl_uct_module_t *) btl;

    if (!uct_btl->initialized) {
        mca_rcache_base_resources_t rcache_resources;
        char *tmp;

        /* NTH: a registration cache shouldn't be necessary when using UCT but there are measurable
         * performance benefits to using rcache/grdma instead of assuming UCT will do the right
         * thing. */
        (void) asprintf (&tmp, "uct.%s", uct_btl->uct_tl_full_name);
        
        rcache_resources.cache_name     = tmp;
        rcache_resources.reg_data       = (void *) uct_btl;
        rcache_resources.sizeof_reg     = sizeof (mca_btl_uct_reg_t) + btl->btl_registration_handle_size;
        rcache_resources.register_mem   = mca_btl_uct_reg_mem;
        rcache_resources.deregister_mem = mca_btl_uct_dereg_mem;

        uct_btl->rcache = mca_rcache_base_module_create ("grdma", uct_btl, &rcache_resources);
        free (tmp);
        if (NULL == uct_btl->rcache) {
            /* something when horribly wrong */
            return OPAL_ERROR;
        }

        uct_btl->initialized = true;
    }

    for (size_t i = 0 ; i < nprocs ; ++i) {
        /* all endpoints are reachable for uct :p */
        peers[i] = mca_btl_uct_endpoint_create (opal_procs[i]);
        if (OPAL_UNLIKELY(NULL == peers[i])) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }

        opal_list_append (&uct_btl->endpoints, &peers[i]->super);

        opal_bitmap_set_bit(reachable, i);
    }

    return OPAL_SUCCESS;
}

static int mca_btl_uct_del_procs (mca_btl_base_module_t *btl, size_t nprocs,
                                  opal_proc_t **procs, mca_btl_base_endpoint_t **peers)
{
    mca_btl_uct_module_t *uct_btl = (mca_btl_uct_module_t *) btl;

    for (size_t i = 0 ; i < nprocs ; ++i) {
        if (peers[i]) {
            opal_list_remove_item (&uct_btl->endpoints, &peers[i]->super);
            OBJ_RELEASE(peers[i]);
        }
    }

    return OPAL_SUCCESS;
}


/**
 * @brief Register a memory region for put/get/atomic operations.
 *
 * @param btl (IN)         BTL module
 * @param endpoint(IN)     BTL addressing information (or NULL for all endpoints)
 * @param base (IN)        Pointer to start of region
 * @param size (IN)        Size of region
 * @param flags (IN)       Flags indicating what operation will be performed. Valid
 *                         values are MCA_BTL_DES_FLAGS_PUT, MCA_BTL_DES_FLAGS_GET,
 *                         and MCA_BTL_DES_FLAGS_ATOMIC
 *
 * @returns a memory registration handle valid for both local and remote operations
 * @returns NULL if the region could not be registered
 *
 * This function registers the specified region with the hardware for use with
 * the btl_put, btl_get, btl_atomic_cas, btl_atomic_op, and btl_atomic_fop
 * functions. Care should be taken to not hold an excessive number of registrations
 * as they may use limited system/NIC resources.
 */
static struct mca_btl_base_registration_handle_t *
mca_btl_uct_register_mem (struct mca_btl_base_module_t *btl, struct mca_btl_base_endpoint_t *endpoint, void *base,
                          size_t size, uint32_t flags)
{
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) btl;
    mca_btl_uct_reg_t *reg;
    int access_flags = flags & MCA_BTL_REG_FLAG_ACCESS_ANY;
    int rc;

    rc = uct_module->rcache->rcache_register (uct_module->rcache, base, size, 0, access_flags,
                                              (mca_rcache_base_registration_t **) &reg);
    if (OPAL_UNLIKELY(OPAL_SUCCESS != rc)) {
        return NULL;
    }

    return &reg->handle;
}

/**
 * @brief Deregister a memory region
 *
 * @param btl (IN)         BTL module region was registered with
 * @param handle (IN)      BTL registration handle to deregister
 *
 * This function deregisters the memory region associated with the specified handle. Care
 * should be taken to not perform any RDMA or atomic operation on this memory region
 * after it is deregistered. It is erroneous to specify a memory handle associated with
 * a remote node.
 */
static int mca_btl_uct_deregister_mem (mca_btl_base_module_t *btl, mca_btl_base_registration_handle_t *handle)
{
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) btl;
    mca_btl_uct_reg_t *reg =
        (mca_btl_uct_reg_t *)((intptr_t) handle - offsetof (mca_btl_uct_reg_t, handle));

    (void) uct_module->rcache->rcache_deregister (uct_module->rcache, &reg->base);

    return OPAL_SUCCESS;
}

static int mca_btl_uct_reg_mem (void *reg_data, void *base, size_t size, mca_rcache_base_registration_t *reg)
{
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) reg_data;
    mca_btl_uct_reg_t *uct_reg = (mca_btl_uct_reg_t *) reg;
    ucs_status_t ucs_status;
    int uct_flags = 0;

    BTL_VERBOSE(("attempting to register range {%p,%p} with uct", base, (char *) base + size));

    if (MCA_BTL_REG_FLAG_REMOTE_READ & reg->access_flags) {
        uct_flags |= UCT_MD_MEM_ACCESS_REMOTE_GET;
    }
    if (MCA_BTL_REG_FLAG_REMOTE_WRITE & reg->access_flags) {
        uct_flags |= UCT_MD_MEM_ACCESS_REMOTE_PUT;
    }
    if (MCA_BTL_REG_FLAG_REMOTE_ATOMIC & reg->access_flags) {
        uct_flags |= UCT_MD_MEM_ACCESS_REMOTE_ATOMIC;
    }

    /* UCT barfs if there are no access flags */
    if (0 == uct_flags) {
        uct_flags = UCT_MD_MEM_ACCESS_ALL;
    }

    printf("btl/uct: register memory: %p, size = %zd, flags = %x\n",
           base, size, uct_flags);
    fflush(stdout);

    ucs_status = uct_md_mem_reg (uct_module->uct_md->uct_md, base, size, uct_flags, &uct_reg->uct_memh);
    if (UCS_OK != ucs_status) {
        BTL_VERBOSE(("Error registering memory with UCT. code: %d", ucs_status));
        return OPAL_ERR_OUT_OF_RESOURCE;
    }

    if (reg->access_flags & (MCA_BTL_REG_FLAG_REMOTE_READ | MCA_BTL_REG_FLAG_REMOTE_WRITE | MCA_BTL_REG_FLAG_REMOTE_ATOMIC)) {
        /* requested registration may be used by a remote process so go ahead and pack
         * the registration handle */
        ucs_status = uct_md_mkey_pack (uct_module->uct_md->uct_md, uct_reg->uct_memh, uct_reg->handle.packed_handle);
        if (OPAL_UNLIKELY(UCS_OK != ucs_status)) {
            BTL_VERBOSE(("Could not pack remote key. code: %d", ucs_status));
            uct_md_mem_dereg (uct_module->uct_md->uct_md, uct_reg->uct_memh);
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
    }

    return OPAL_SUCCESS;
}

static int mca_btl_uct_dereg_mem (void *reg_data, mca_rcache_base_registration_t *reg)
{
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) reg_data;
    mca_btl_uct_reg_t *uct_reg = (mca_btl_uct_reg_t *) reg;

    uct_md_mem_dereg (uct_module->uct_md->uct_md, uct_reg->uct_memh);

    return OPAL_SUCCESS;
}


/*
 * Cleanup/release module resources.
 */

int mca_btl_uct_finalize (mca_btl_base_module_t* btl)
{
    mca_btl_uct_module_t *uct_btl = (mca_btl_uct_module_t *) btl;
    mca_btl_uct_endpoint_t *endpoint, *next;

    /* clean up any leftover endpoints */
    OPAL_LIST_FOREACH_SAFE(endpoint, next, &uct_btl->endpoints, mca_btl_uct_endpoint_t) {
        opal_list_remove_item (&uct_btl->endpoints, &endpoint->super);
        OBJ_RELEASE(endpoint);
    }

    for (int context_id = 0 ; context_id < uct_btl->uct_worker_count ; ++context_id) {
        mca_btl_uct_context_fini (uct_btl, uct_btl->contexts + context_id);
    }

    if (uct_btl->rcache) {
        mca_rcache_base_module_destroy (uct_btl->rcache);
    }

    if (uct_btl->uct_tl_config) {
        uct_config_release (uct_btl->uct_tl_config);
    }

    free (uct_btl->uct_tl_full_name);
    free (uct_btl->uct_tl_name);
    free (uct_btl->uct_dev_name);

    ucs_async_context_destroy (uct_btl->ucs_async);

    OBJ_DESTRUCT(&uct_btl->endpoints);
    OBJ_RELEASE(uct_btl->uct_md);
    free (btl);

    return OPAL_SUCCESS;
}

mca_btl_uct_module_t mca_btl_uct_module_template = {
    .super = {
        /* initialize functions. this btl only support RDMA and atomics
         * for now so it does not provide prepare_src, alloc, free, or send */
        .btl_component      = &mca_btl_uct_component.super,
        .btl_add_procs      = mca_btl_uct_add_procs,
        .btl_del_procs      = mca_btl_uct_del_procs,
        .btl_finalize       = mca_btl_uct_finalize,
        .btl_put            = mca_btl_uct_put,
        .btl_get            = mca_btl_uct_get,
        .btl_register_mem   = mca_btl_uct_register_mem,
        .btl_deregister_mem = mca_btl_uct_deregister_mem,
        .btl_atomic_op      = mca_btl_uct_aop,
        .btl_atomic_fop     = mca_btl_uct_afop,
        .btl_atomic_cswap   = mca_btl_uct_acswap,
        .btl_flush          = mca_btl_uct_flush,

        /* set the default flags for this btl. uct provides us with rdma and both
         * fetching and non-fetching atomics (though limited to add and cswap) */
        .btl_flags          = MCA_BTL_FLAGS_RDMA | MCA_BTL_FLAGS_ATOMIC_FOPS | MCA_BTL_FLAGS_ATOMIC_OPS,
        .btl_atomic_flags   = MCA_BTL_ATOMIC_SUPPORTS_ADD | MCA_BTL_ATOMIC_SUPPORTS_CSWAP |
                              MCA_BTL_ATOMIC_SUPPORTS_SWAP | MCA_BTL_ATOMIC_SUPPORTS_32BIT,

        /* set the default limits on put and get */
        .btl_put_limit      = 1 << 23,
        .btl_put_alignment  = 0,
        .btl_get_limit      = 1 << 23,
        .btl_get_alignment  = 0,
   }
};

OBJ_CLASS_INSTANCE(mca_btl_uct_reg_t, opal_free_list_item_t, NULL, NULL);

void mca_btl_uct_md_construct (mca_btl_uct_md_t *md)
{
    md->uct_md = NULL;
}

void mca_btl_uct_md_destruct (mca_btl_uct_md_t *md)
{
    if (md->uct_md) {
        uct_md_close (md->uct_md);
        md->uct_md = NULL;
    }
}

OBJ_CLASS_INSTANCE(mca_btl_uct_md_t, opal_object_t, mca_btl_uct_md_construct, mca_btl_uct_md_destruct);
