/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2004-2007 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2005 The University of Tennessee and The University
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

#include "opal/mca/btl/btl.h"
#include "opal/mca/btl/base/base.h"
#include "opal/mca/hwloc/base/base.h"

#include <string.h>

#include "btl_uct.h"

static uint64_t mca_btl_uct_cap_to_btl_flag[][2] = {
    {UCT_IFACE_FLAG_PUT_ZCOPY, MCA_BTL_FLAGS_PUT},
    {UCT_IFACE_FLAG_GET_ZCOPY, MCA_BTL_FLAGS_GET},
    /* at this time the UCT btl implements non-fetching atomics with the fetching ones */
    {UCT_IFACE_FLAG_ATOMIC_FADD64, MCA_BTL_FLAGS_ATOMIC_FOPS | MCA_BTL_FLAGS_ATOMIC_OPS},
    {0, },
};

static uint64_t mca_btl_uct_cap_to_btl_atomic_flag[][2] = {
    {UCT_IFACE_FLAG_ATOMIC_ADD64, MCA_BTL_ATOMIC_SUPPORTS_ADD},
    {UCT_IFACE_FLAG_ATOMIC_ADD32, MCA_BTL_ATOMIC_SUPPORTS_32BIT},
    {UCT_IFACE_FLAG_ATOMIC_CSWAP64, MCA_BTL_ATOMIC_SUPPORTS_CSWAP},
    {UCT_IFACE_FLAG_ATOMIC_SWAP64, MCA_BTL_ATOMIC_SUPPORTS_SWAP},
    {UCT_IFACE_FLAG_ATOMIC_CPU, MCA_BTL_ATOMIC_SUPPORTS_GLOB},
    {0, },
};

/**
 * @brief Convert UCT capability flags to BTL flags
 *
 * @param[in] cap_flags  UCT capability flags
 *
 * @returns equivalent BTL flags
 */
static int32_t mca_btl_uct_module_flags (uint64_t cap_flags)
{
    uint32_t flags = 0;
    for (int i = 0 ; mca_btl_uct_cap_to_btl_flag[i][0] > 0 ; ++i) {
        if (cap_flags & mca_btl_uct_cap_to_btl_flag[i][0]) {
            flags |= (uint32_t) mca_btl_uct_cap_to_btl_flag[i][1];
        }
    }
    return flags;
}

/**
 * @brief Convert UCT capability flags to BTL atomic flags
 *
 * @param[in] cap_flags  UCT capability flags
 *
 * @returns equivalent BTL atomic flags
 */
static int32_t mca_btl_uct_module_atomic_flags (uint64_t cap_flags)
{
    uint32_t flags = 0;
    for (int i = 0 ; mca_btl_uct_cap_to_btl_atomic_flag[i][0] > 0 ; ++i) {
        if (cap_flags & mca_btl_uct_cap_to_btl_atomic_flag[i][0]) {
            flags |= (uint32_t) mca_btl_uct_cap_to_btl_atomic_flag[i][1];
        }
    }
    return flags;
}

static int mca_btl_uct_component_register(void)
{
    mca_btl_uct_module_t *module = &mca_btl_uct_module_template;

    mca_btl_uct_component.transports = "none";
    (void) mca_base_component_var_register(&mca_btl_uct_component.super.btl_version,
                                           "transports", "Comma-delimited list of transports of the form "
                                           "md_name-tl_name to use for communication. Transports MUST support "
                                           "put, get, and amos. Special values: all (all available), none. "
                                           "(default: none)", MCA_BASE_VAR_TYPE_STRING, NULL, 0,
                                           MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3, MCA_BASE_VAR_SCOPE_LOCAL,
                                           &mca_btl_uct_component.transports);

    mca_btl_uct_component.num_contexts_per_module = 0;
    (void) mca_base_component_var_register(&mca_btl_uct_component.super.btl_version,
                                           "num_contexts_per_module", "Number of UCT worker contexts "
                                           "to create for each BTL module. Larger numbers will improve "
                                           "multi-threaded performance but may increase memory usage. "
                                           "A good rule of thumb is one context per application thread "
                                           "that will be calling into MPI. (default: 0 -- autoselect "
                                           "based on the number of cores)", MCA_BASE_VAR_TYPE_INT,
                                           NULL, 0 ,MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3,
                                           MCA_BASE_VAR_SCOPE_ALL, &mca_btl_uct_component.num_contexts_per_module);

#if OPAL_C_HAVE__THREAD_LOCAL
    mca_btl_uct_component.bind_threads_to_contexts = true;
    (void) mca_base_component_var_register(&mca_btl_uct_component.super.btl_version,
                                           "bind_threads_to_contexts", "Bind threads to device contexts. "
                                           "In general this should improve the multi-threaded performance "
                                           "when threads are used. (default: true)", MCA_BASE_VAR_TYPE_BOOL,
                                           NULL, 0 ,MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3,
                                           MCA_BASE_VAR_SCOPE_ALL, &mca_btl_uct_component.bind_threads_to_contexts);
#endif
                                           
    /* for now we want this component to lose to btl/ugni and btl/vader */
    module->super.btl_exclusivity = MCA_BTL_EXCLUSIVITY_HIGH - 50;

    return mca_btl_base_param_register (&mca_btl_uct_component.super.btl_version,
                                        &module->super);
}

static int mca_btl_uct_component_open(void)
{
    if (0 == mca_btl_uct_component.num_contexts_per_module) {
        /* use the core count and the number of local processes to determine
         * how many UCT workers to create */
        int core_count;

        (void) opal_hwloc_base_get_topology ();
        core_count = hwloc_get_nbobjs_by_type (opal_hwloc_topology, HWLOC_OBJ_CORE);

        if (core_count <= opal_process_info.num_local_peers || !opal_using_threads()) {
            /* there is probably no benefit to using multiple device contexts when not
             * using threads or oversubscribing the node with mpi processes. */
            mca_btl_uct_component.num_contexts_per_module = 1;
        } else {
            mca_btl_uct_component.num_contexts_per_module = core_count / (opal_process_info.num_local_peers + 1);
        }

        opal_hwloc_base_free_topology (opal_hwloc_topology);
        opal_hwloc_topology = NULL;
    }

    return OPAL_SUCCESS;
}


/*
 * component cleanup - sanity checking of queue lengths
 */
static int mca_btl_uct_component_close(void)
{
    return OPAL_SUCCESS;
}

static int mca_btl_uct_modex_send (void)
{
    size_t modex_size = sizeof (mca_btl_uct_modex_t);
    mca_btl_uct_modex_t *modex;
    uint8_t *modex_data;
    int rc;

    for (unsigned i = 0 ; i < mca_btl_uct_component.module_count ; ++i) {
        mca_btl_uct_module_t *module = mca_btl_uct_component.modules[i];

        modex_size += (3 + 4 + module->uct_iface_attr.device_addr_len + module->uct_iface_attr.iface_addr_len +
                       strlen (module->uct_tl_full_name) + 1) & ~3;
    }

    modex = alloca (modex_size);
    modex_data = modex->data;

    modex->module_count = mca_btl_uct_component.module_count;

    for (unsigned i = 0 ; i < mca_btl_uct_component.module_count ; ++i) {
        mca_btl_uct_module_t *module = mca_btl_uct_component.modules[i];
        size_t name_len = strlen (module->uct_tl_full_name);

        /* pack the size */
        *((uint32_t *) modex_data) = (3 + 4 + module->uct_iface_attr.device_addr_len + module->uct_iface_attr.iface_addr_len +
                                     strlen (module->uct_tl_full_name) + 1) & ~3;
        modex_data += 4;

        strcpy (modex_data, module->uct_tl_full_name);
        modex_data += name_len + 1;

        /* NTH: only the first context is available. i assume the device addresses of the
         * contexts will be the same but they will have different iface addresses. i also
         * am assuming that it doesn't really matter if all remote contexts connect to
         * the same endpoint since we are only doing RDMA. if any of these assumptions are
         * wrong then we can't delay creating the other contexts and must include their
         * information in the modex. */
        uct_iface_get_address (module->contexts[0].uct_iface, (uct_iface_addr_t *) modex_data);
        modex_data += module->uct_iface_attr.iface_addr_len;

        uct_iface_get_device_address (module->contexts[0].uct_iface, (uct_device_addr_t *) modex_data);
        modex_data = (uint8_t *) (((uintptr_t)modex_data + module->uct_iface_attr.device_addr_len + 3) & ~3);
    }

    OPAL_MODEX_SEND(rc, OPAL_PMIX_GLOBAL, &mca_btl_uct_component.super.btl_version, modex, modex_size);
    return rc;
}

int mca_btl_uct_context_init (mca_btl_uct_module_t *module, mca_btl_uct_device_context_t *context)
{
    uct_iface_params_t iface_params = {.rndv_cb = NULL, .eager_cb = NULL, .stats_root = NULL,
                                       .rx_headroom = 0, .open_mode = UCT_IFACE_OPEN_MODE_DEVICE,
                                       .mode = {.device = {.tl_name = module->uct_tl_name,
                                                           .dev_name = module->uct_dev_name}}};
    ucs_status_t ucs_status;
    int rc = OPAL_SUCCESS;

    mca_btl_uct_context_lock (context);

    do {
        if (NULL != context->uct_worker) {
            break;
        }

        /* apparently (in contradiction to the spec) UCT is *not* thread safe. because we have to
         * use our own locks just go ahead and use UCS_THREAD_MODE_SINGLE. if they ever fix their
         * api then change this back to UCS_THREAD_MODE_MULTI and remove the locks around the
         * various UCT calls. */
        ucs_status = uct_worker_create (module->ucs_async, UCS_THREAD_MODE_SINGLE, &context->uct_worker);
        if (UCS_OK != ucs_status) {
            BTL_VERBOSE(("Could not create a UCT worker"));
            rc = OPAL_ERROR;
            break;
        }

        ucs_status = uct_iface_open (module->uct_md->uct_md, context->uct_worker, &iface_params,
                                     module->uct_tl_config, &context->uct_iface);
        if (UCS_OK != ucs_status) {
            BTL_VERBOSE(("Could not open UCT interface"));
            rc = OPAL_ERROR;
            break;
        }
    } while (0);

    mca_btl_uct_context_unlock (context);

    return rc;
}

void mca_btl_uct_context_fini (mca_btl_uct_module_t *module, mca_btl_uct_device_context_t *context)
{
    if (context->uct_iface) {
        uct_iface_close (context->uct_iface);
        context->uct_iface = NULL;
    }

    if (context->uct_worker) {
        uct_worker_destroy (context->uct_worker);
        context->uct_worker = NULL;
    }
}

static int mca_btl_uct_component_process_uct_tl (const char *md_name, mca_btl_uct_md_t *md,
                                                 uct_tl_resource_desc_t *tl_desc,
                                                 char **allowed_ifaces, size_t registration_size)
{
    const uint64_t required_flags = UCT_IFACE_FLAG_PUT_ZCOPY | UCT_IFACE_FLAG_GET_ZCOPY |
        UCT_IFACE_FLAG_ATOMIC_FADD64 | UCT_IFACE_FLAG_ATOMIC_CSWAP64;
    bool found_matching_tl = false;
    mca_btl_uct_module_t *module;
    ucs_status_t ucs_status;
    char *tl_full_name;
    int rc;

    rc = asprintf (&tl_full_name, "%s-%s", md_name, tl_desc->tl_name);
    if (0 > rc) {
        return OPAL_ERR_OUT_OF_RESOURCE;
    }

    for (int l = 0 ; allowed_ifaces[l] ; ++l) {
        if (0 == strcmp (tl_full_name, allowed_ifaces[l]) || 0 == strcmp (allowed_ifaces[l], "all")) {
            found_matching_tl = true;
            break;
        }
    }

    if (!found_matching_tl) {
        BTL_VERBOSE(("no allowed iface matches %s\n", tl_full_name));
        free (tl_full_name);
        return OPAL_SUCCESS;
    }

    module = malloc (sizeof (*module));
    if (NULL == module) {
        free (tl_full_name);
        return OPAL_ERR_OUT_OF_RESOURCE;
    }

    /* copy the module template */
    *module = mca_btl_uct_module_template;

    OBJ_CONSTRUCT(&module->endpoints, opal_list_t);

    module->uct_md = md;
    /* keep a reference to the memory domain */
    OBJ_RETAIN(md);

    module->uct_worker_count = mca_btl_uct_component.num_contexts_per_module;
    module->uct_tl_name = strdup (tl_desc->tl_name);
    module->uct_dev_name = strdup (tl_desc->dev_name);
    module->uct_tl_full_name = tl_full_name;

    ucs_status = ucs_async_context_create (UCS_ASYNC_MODE_THREAD, &module->ucs_async);
    if (UCS_OK != ucs_status) {
        BTL_VERBOSE(("Could not create a UCT async context"));
        mca_btl_uct_finalize (&module->super);
        return OPAL_ERROR;
    }

    (void) uct_md_iface_config_read (md->uct_md, tl_desc->tl_name, NULL, NULL,
                                     &module->uct_tl_config);

    for (int context_id = 0 ; context_id < module->uct_worker_count ; ++context_id) {
        module->contexts[context_id].context_id = context_id;
    }

    /* always initialize the first context */
    rc = mca_btl_uct_context_init (module, module->contexts);
    if (OPAL_UNLIKELY(OPAL_SUCCESS != rc)) {
        mca_btl_uct_finalize (&module->super);
        return rc;
    }

    /* only need to query one of the interfaces to get the attributes */
    ucs_status = uct_iface_query (module->contexts[0].uct_iface, &module->uct_iface_attr);
    if (UCS_OK != ucs_status) {
        BTL_VERBOSE(("Error querying UCT interface"));
        mca_btl_uct_finalize (&module->super);
        return OPAL_ERROR;
    }

    /* UCT bandwidth is in bytes/sec, BTL is in MB/sec */
    module->super.btl_bandwidth = (uint32_t) (module->uct_iface_attr.bandwidth / 1048576.0);
    /* TODO -- figure out how to translate UCT latency to us */
    module->super.btl_latency = 1;
    module->super.btl_registration_handle_size = registration_size;

    if ((module->uct_iface_attr.cap.flags & required_flags) != required_flags) {
        BTL_VERBOSE(("Requested UCT transport does not support required features (put, get, amo)"));
        mca_btl_uct_finalize (&module->super);
        /* not really an error. just an unusable transport */
        return OPAL_SUCCESS;
    }

    module->super.btl_flags = mca_btl_uct_module_flags (module->uct_iface_attr.cap.flags);
    module->super.btl_atomic_flags = mca_btl_uct_module_atomic_flags (module->uct_iface_attr.cap.flags);
    module->super.btl_get_limit = module->uct_iface_attr.cap.get.max_zcopy;
    module->super.btl_put_limit = module->uct_iface_attr.cap.put.max_zcopy;
    module->super.btl_get_local_registration_threshold = 0;
    /* no registration needed when using short put */
    module->super.btl_put_local_registration_threshold = module->uct_iface_attr.cap.put.max_short;

    mca_btl_uct_component.modules[mca_btl_uct_component.module_count++] = module;

    return OPAL_SUCCESS;
}

static int mca_btl_uct_component_process_uct_md (uct_md_resource_desc_t *md_desc, char **allowed_ifaces)
{
    uct_tl_resource_desc_t *tl_desc;
    uct_md_config_t *uct_config;
    uct_md_attr_t md_attr;
    mca_btl_uct_md_t *md;
    bool found = false;
    unsigned num_tls;
    int rc;

    for (int j = 0 ; allowed_ifaces[j] ; ++j) {
        if (0 == strncmp (allowed_ifaces[j], md_desc->md_name, strlen (md_desc->md_name)) ||
            0 == strcmp (allowed_ifaces[j], "all")) {
            found = true;
            break;
        }
    }

    if (!found) {
        /* nothing to do */
        return OPAL_SUCCESS;
    }

    md = OBJ_NEW(mca_btl_uct_md_t);

    uct_md_config_read (md_desc->md_name, NULL, NULL, &uct_config);
    uct_md_open (md_desc->md_name, uct_config, &md->uct_md);
    uct_config_release (uct_config);

    uct_md_query (md->uct_md, &md_attr);
    uct_md_query_tl_resources (md->uct_md, &tl_desc, &num_tls);

    for (unsigned j = 0 ; j < num_tls ; ++j) {
        rc = mca_btl_uct_component_process_uct_tl (md_desc->md_name, md, tl_desc + j, allowed_ifaces,
                                                   md_attr.rkey_packed_size);
        if (OPAL_SUCCESS != rc) {
            return rc;
        }

        if (MCA_BTL_UCT_MAX_MODULES == mca_btl_uct_component.module_count) {
            BTL_VERBOSE(("Created the maximum number of allowable modules"));
            break;
        }
    }

    uct_release_tl_resource_list (tl_desc);

    /* release the initial reference to the md object. if any modules were created the UCT md will remain
     * open until those modules are finalized. */
    OBJ_RELEASE(md);

    return OPAL_SUCCESS;
}

/*
 *  UCT component initialization:
 *  (1) read interface list from kernel and compare against component parameters
 *      then create a BTL instance for selected interfaces
 *  (2) setup UCT listen socket for incoming connection attempts
 *  (3) register BTL parameters with the MCA
 */

static mca_btl_base_module_t **mca_btl_uct_component_init (int *num_btl_modules, bool enable_progress_threads,
                                                           bool enable_mpi_threads)
{
    /* for this BTL to be useful the interface needs to support RDMA and certain atomic operations */
    struct mca_btl_base_module_t **base_modules;
    uct_md_resource_desc_t *resources;
    unsigned resource_count;
    char **allowed_ifaces;
    int rc;

    BTL_VERBOSE(("initializing uct btl"));

    if (NULL == mca_btl_uct_component.transports || 0 == strlen (mca_btl_uct_component.transports) ||
        0 == strcmp (mca_btl_uct_component.transports, "none")) {
        BTL_VERBOSE(("no uct transports specified"));
        return NULL;
    }

    {
        static volatile int delay = 0;
        while( delay ){
            sleep(1);
        }
    }

    allowed_ifaces = opal_argv_split (mca_btl_uct_component.transports, ',');
    if (NULL == allowed_ifaces) {
        return NULL;
    }

    uct_query_md_resources (&resources, &resource_count);

    mca_btl_uct_component.module_count = 0;

    /* generate all suitable btl modules */
    for (unsigned i = 0 ; i < resource_count ; ++i) {
        rc = mca_btl_uct_component_process_uct_md (resources + i, allowed_ifaces);
        if (OPAL_SUCCESS != rc) {
            break;
        }
    }

    opal_argv_free (allowed_ifaces);
    uct_release_md_resource_list (resources);

    mca_btl_uct_modex_send ();

    /* pass module array back to caller */
    base_modules = calloc (mca_btl_uct_component.module_count, sizeof (*base_modules));
    if (NULL == base_modules) {
        return NULL;
    }

    memcpy (base_modules, mca_btl_uct_component.modules, mca_btl_uct_component.module_count *
            sizeof (mca_btl_uct_component.modules[0]));

    *num_btl_modules = mca_btl_uct_component.module_count;

    BTL_VERBOSE(("uct btl initialization complete. found %d suitable transports",
                 mca_btl_uct_component.module_count));

    return base_modules;
}

/**
 * @brief UCT BTL progress function
 *
 * This function explictly progresses all workers.
 */
static int mca_btl_uct_component_progress (void)
{
    unsigned ret = 0;

    for (unsigned i = 0 ; i < mca_btl_uct_component.module_count ; ++i) {
        mca_btl_uct_module_t *module = mca_btl_uct_component.modules[i];
        /* unlike ucp, uct actually tells us something useful! its almost like it was "inspired"
         * by the btl progress functions.... */
        for (int j = 0 ; j < module->uct_worker_count ; ++j) {
            ret += mca_btl_uct_context_progress (module->contexts + j);
        }
    }

    return (int) ret;
}


/** UCT btl component */
mca_btl_uct_component_t mca_btl_uct_component = {
    .super = {
        .btl_version = {
            MCA_BTL_DEFAULT_VERSION("uct"),
            .mca_open_component = mca_btl_uct_component_open,
            .mca_close_component = mca_btl_uct_component_close,
            .mca_register_component_params = mca_btl_uct_component_register,
        },
        .btl_data = {
            /* The component is not checkpoint ready */
            .param_field = MCA_BASE_METADATA_PARAM_NONE
        },

        .btl_init = mca_btl_uct_component_init,
        .btl_progress = mca_btl_uct_component_progress,
    }
};
