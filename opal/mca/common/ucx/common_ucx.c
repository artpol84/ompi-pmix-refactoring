/*
 * Copyright (C) Mellanox Technologies Ltd. 2018. ALL RIGHTS RESERVED.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "opal_config.h"

#include "common_ucx.h"
#include "opal/mca/base/mca_base_var.h"
#include "opal/mca/base/mca_base_framework.h"
#include "opal/mca/pmix/pmix.h"
#include "opal/memoryhooks/memory.h"

#include <ucm/api/ucm.h>

/***********************************************************************/

extern mca_base_framework_t opal_memory_base_framework;

opal_common_ucx_module_t opal_common_ucx = {
    .verbose             = 0,
    .progress_iterations = 100,
    .registered          = 0,
    .opal_mem_hooks      = 0
};

static void opal_common_ucx_mem_release_cb(void *buf, size_t length,
                                           void *cbdata, bool from_alloc)
{
    ucm_vm_munmap(buf, length);
}

OPAL_DECLSPEC void opal_common_ucx_mca_var_register(const mca_base_component_t *component)
{
    static int registered = 0;
    static int hook_index;
    static int verbose_index;
    static int progress_index;
    if (!registered) {
        verbose_index = mca_base_var_register("opal", "opal_common", "ucx", "verbose",
                                              "Verbose level of the UCX components",
                                              MCA_BASE_VAR_TYPE_INT, NULL, 0,
                                              MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3,
                                              MCA_BASE_VAR_SCOPE_LOCAL,
                                              &opal_common_ucx.verbose);
        progress_index = mca_base_var_register("opal", "opal_common", "ucx", "progress_iterations",
                                               "Set number of calls of internal UCX progress "
                                               "calls per opal_progress call",
                                               MCA_BASE_VAR_TYPE_INT, NULL, 0,
                                               MCA_BASE_VAR_FLAG_SETTABLE, OPAL_INFO_LVL_3,
                                               MCA_BASE_VAR_SCOPE_LOCAL,
                                               &opal_common_ucx.progress_iterations);
        hook_index = mca_base_var_register("opal", "opal_common", "ucx", "opal_mem_hooks",
                                           "Use OPAL memory hooks, instead of UCX internal "
                                           "memory hooks", MCA_BASE_VAR_TYPE_BOOL, NULL, 0, 0,
                                           OPAL_INFO_LVL_3,
                                           MCA_BASE_VAR_SCOPE_LOCAL,
                                           &opal_common_ucx.opal_mem_hooks);
        registered = 1;
    }
    if (component) {
        mca_base_var_register_synonym(verbose_index, component->mca_project_name,
                                      component->mca_type_name,
                                      component->mca_component_name,
                                      "verbose", 0);
        mca_base_var_register_synonym(progress_index, component->mca_project_name,
                                      component->mca_type_name,
                                      component->mca_component_name,
                                      "progress_iterations", 0);
        mca_base_var_register_synonym(hook_index, component->mca_project_name,
                                      component->mca_type_name,
                                      component->mca_component_name,
                                      "opal_mem_hooks", 0);
    }
}

OPAL_DECLSPEC void opal_common_ucx_mca_register(void)
{
    int ret;

    opal_common_ucx.registered++;
    if (opal_common_ucx.registered > 1) {
        /* process once */
        return;
    }

    opal_common_ucx.output = opal_output_open(NULL);
    opal_output_set_verbosity(opal_common_ucx.output, opal_common_ucx.verbose);

    ret = mca_base_framework_open(&opal_memory_base_framework, 0);
    if (OPAL_SUCCESS != ret) {
        /* failed to initialize memory framework - just exit */
        MCA_COMMON_UCX_VERBOSE(1, "failed to initialize memory base framework: %d, "
                                  "memory hooks will not be used", ret);
        return;
    }

    /* Set memory hooks */
    if (opal_common_ucx.opal_mem_hooks &&
        (OPAL_MEMORY_FREE_SUPPORT | OPAL_MEMORY_MUNMAP_SUPPORT) ==
        ((OPAL_MEMORY_FREE_SUPPORT | OPAL_MEMORY_MUNMAP_SUPPORT) &
         opal_mem_hooks_support_level()))
    {
        MCA_COMMON_UCX_VERBOSE(1, "%s", "using OPAL memory hooks as external events");
        ucm_set_external_event(UCM_EVENT_VM_UNMAPPED);
        opal_mem_hooks_register_release(opal_common_ucx_mem_release_cb, NULL);
    }
}

OPAL_DECLSPEC void opal_common_ucx_mca_deregister(void)
{
    /* unregister only on last deregister */
    opal_common_ucx.registered--;
    assert(opal_common_ucx.registered >= 0);
    if (opal_common_ucx.registered) {
        return;
    }
    opal_mem_hooks_unregister_release(opal_common_ucx_mem_release_cb);
    opal_output_close(opal_common_ucx.output);
}

void opal_common_ucx_empty_complete_cb(void *request, ucs_status_t status)
{
}

static void opal_common_ucx_mca_fence_complete_cb(int status, void *fenced)
{
    *(int*)fenced = 1;
}

OPAL_DECLSPEC int opal_common_ucx_mca_pmix_fence(ucp_worker_h worker)
{
    volatile int fenced = 0;
    int ret = OPAL_SUCCESS;

    if (OPAL_SUCCESS != (ret = opal_pmix.fence_nb(NULL, 0,
                    opal_common_ucx_mca_fence_complete_cb, (void*)&fenced))){
        return ret;
    }

    while (!fenced) {
        ucp_worker_progress(worker);
    }

    return ret;
}


static void opal_common_ucx_wait_all_requests(void **reqs, int count, ucp_worker_h worker)
{
    int i;

    MCA_COMMON_UCX_VERBOSE(2, "waiting for %d disconnect requests", count);
    for (i = 0; i < count; ++i) {
        opal_common_ucx_wait_request(reqs[i], worker, "ucp_disconnect_nb");
        reqs[i] = NULL;
    }
}

OPAL_DECLSPEC int opal_common_ucx_del_procs(opal_common_ucx_del_proc_t *procs, size_t count,
                                            size_t my_rank, size_t max_disconnect, ucp_worker_h worker)
{
    size_t num_reqs;
    size_t max_reqs;
    void *dreq, **dreqs;
    size_t i;
    size_t n;
    int ret = OPAL_SUCCESS;

    MCA_COMMON_UCX_ASSERT(procs || !count);
    MCA_COMMON_UCX_ASSERT(max_disconnect > 0);

    max_reqs = (max_disconnect > count) ? count : max_disconnect;

    dreqs = malloc(sizeof(*dreqs) * max_reqs);
    if (dreqs == NULL) {
        return OPAL_ERR_OUT_OF_RESOURCE;
    }

    num_reqs = 0;

    for (i = 0; i < count; ++i) {
        n = (i + my_rank) % count;
        if (procs[n].ep == NULL) {
            continue;
        }

        MCA_COMMON_UCX_VERBOSE(2, "disconnecting from rank %zu", procs[n].vpid);
        dreq = ucp_disconnect_nb(procs[n].ep);
        if (dreq != NULL) {
            if (UCS_PTR_IS_ERR(dreq)) {
                MCA_COMMON_UCX_ERROR("ucp_disconnect_nb(%zu) failed: %s", procs[n].vpid,
                                     ucs_status_string(UCS_PTR_STATUS(dreq)));
                continue;
            } else {
                dreqs[num_reqs++] = dreq;
                if (num_reqs >= max_disconnect) {
                    opal_common_ucx_wait_all_requests(dreqs, num_reqs, worker);
                    num_reqs = 0;
                }
            }
        }
    }
    /* num_reqs == 0 is processed by opal_common_ucx_wait_all_requests routine,
     * so suppress coverity warning */
    /* coverity[uninit_use_in_call] */
    opal_common_ucx_wait_all_requests(dreqs, num_reqs, worker);
    free(dreqs);

    if (OPAL_SUCCESS != (ret = opal_common_ucx_mca_pmix_fence(worker))) {
        return ret;
    }

    return OPAL_SUCCESS;
}

/* ----------------------------------------------------------------------------- */

typedef struct  {
    opal_mutex_t mutex;
    ucp_worker_h worker;
    ucp_ep_h *endpoints;
    int commsize;
} _worker_engine_t;

typedef struct {
    int ctx_id;
    _worker_engine_t *worker;
} _thr_local_cctx_t;

typedef struct {
    _worker_engine_t *worker;
    ucp_rkey_h *rkeys;
} _mem_info_t;

typedef struct {
    int ctx_id;
    _mem_info_t *mem;
} _thr_local_mem_t;


typedef struct {
    opal_list_item_t super;
    _worker_engine_t *ptr;
} _idle_list_item_t;
OBJ_CLASS_DECLARATION(_idle_list_item_t);
OBJ_CLASS_INSTANCE(_idle_list_item_t, opal_list_item_t, NULL, NULL);


typedef struct {
    // A pointer arrays to a thread-local table records
    _thr_local_cctx_t **ctx_tbl;
    size_t ctx_tbl_size;
    // A pointer arrays to a thread-local table records
    _thr_local_mem_t **mem_tbl;
    size_t mem_tbl_size;
} _thr_local_table;

typedef struct {
    opal_list_item_t super;
    _worker_engine_t *ptr;
} _worker_list_item_t;
OBJ_CLASS_DECLARATION(_idle_list_item_t);
OBJ_CLASS_INSTANCE(_idle_list_item_t, opal_list_item_t, NULL, NULL);

typedef struct {
    opal_list_item_t super;
    _worker_engine_t *ptr;
} _mem_region_list_item_t;
OBJ_CLASS_DECLARATION(_idle_list_item_t);
OBJ_CLASS_INSTANCE(_idle_list_item_t, opal_list_item_t, NULL, NULL);


typedef

static pthread_key_t _tlocal_key;


static ucp_worker_h _create_ctx_worker(opal_common_ucx_wpool_t *wpool)
{
    ucp_worker_params_t worker_params;
    ucp_worker_h worker;
    ucs_status_t status;
    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
    status = ucp_worker_create(wpool->ucp_ctx, &worker_params, &worker);
    if (UCS_OK != status) {
        return NULL;
    }
    return worker;
}

static _worker_engine_t *_create_ctx_tlocal(ucp_worker_h worker, size_t commsize)
{
    _worker_engine_t *ctx_loc = calloc(1, sizeof(_worker_engine_t));
    ctx_loc->worker = worker;
    OBJ_CONSTRUCT(&ctx_loc->mutex, opal_mutex_t);
    ctx_loc->commsize = commsize;
    if( 0 != commsize ){
        ctx_loc->endpoints = calloc(commsize, sizeof(*ctx_loc->endpoints));
    } else {
        ctx_loc->endpoints = NULL;
    }
}

int _wpool_add_to_idle(opal_common_ucx_wpool_t *wpool,
                       _worker_engine_t *lctx)
{
    opal_mutex_lock(wpool->mutex);
    if( 0!= lctx->commsize ) {
        // TODO: clear all endpoints and set commsize t 0
    }
    _idle_list_item_t *item = OBJ_NEW(_idle_list_item_t);
    item->ptr = lctx;
    opal_list_append(&wpool->idle_workers, &item->super);
    opal_mutex_unlock(wpool->mutex);
}

_worker_engine_t *_wpool_get_from_idle(opal_common_ucx_wpool_t *wpool)
{
    // TODO
}


static inline void _cleanup_tlocal(void *arg)
{
    // 1. Cleanup all rkeys in the window table
    // 2. Return all workers into the idle pool
}

int opal_common_ucx_wpool_init(opal_common_ucx_wpool_t *wpool,
                               ucp_request_init_callback_t req_init_ptr,
                               size_t req_size)
{
    ucp_config_t *config = NULL;
    ucp_params_t context_params;
    ucp_worker_params_t worker_params;

    wpool->cur_ctxid = wpool->cur_memid = 0;

    status = ucp_config_read("MPI", NULL, &config);
    if (UCS_OK != status) {
        OSC_UCX_VERBOSE(1, "ucp_config_read failed: %d", status);
        return OPAL_ERROR;
    }

    /* initialize UCP context */
    memset(&context_params, 0, sizeof(context_params));
    context_params.field_mask = UCP_PARAM_FIELD_FEATURES |
            UCP_PARAM_FIELD_MT_WORKERS_SHARED |
            UCP_PARAM_FIELD_ESTIMATED_NUM_EPS |
            UCP_PARAM_FIELD_REQUEST_INIT |
            UCP_PARAM_FIELD_REQUEST_SIZE;
    context_params.features = UCP_FEATURE_RMA | UCP_FEATURE_AMO32 | UCP_FEATURE_AMO64;
    context_params.mt_workers_shared = 1;
    context_params.estimated_num_eps = ompi_proc_world_size();
    context_params.request_init = internal_req_init;
    context_params.request_size = req_size;

    status = ucp_init(&context_params, config, &wpool->ucp_ctx);
    ucp_config_release(config);
    if (UCS_OK != status) {
        OSC_UCX_VERBOSE(1, "ucp_init failed: %d", status);
        ret = OPAL_ERROR;
        goto err_ucp_init;
    }

    wpool->idle_workers = OBJ_NEW(_idle_list_item_t);
    wpool->recv_worker = _create_ctx_worker(wpool);
    if(NULL == wpool->recv_worker) {
        OSC_UCX_VERBOSE(1, "_create_ctx_worker failed");
        ret = OMPI_ERROR;
        goto err_worker;
    }

    status = ucp_worker_get_address(mca_osc_ucx_component.ucp_worker,
                                    &wpool->recv_waddr, &wpool->recv_waddr_len);
    if (status != UCS_OK) {
        OSC_UCX_VERBOSE(1, "ucp_worker_get_address failed: %d", status);
        ret = OMPI_ERROR;
        goto err_get_addr;
    }

    _wpool_add_to_idle(wpool, _create_ctx_tlocal(worker, 0));

    pthread_key_create(&_tlocal_key, opal_common_ucx_cleanup_local_worker);

err_get_addr:
    if(NULL != wpool->recv_worker) {
        ucp_worker_destroy(wpool->recv_worker);
    }
err_worker:
    ucp_cleanup(wpool->ucp_ctx);
err_ucp_init:
   return ret;
}


int opal_common_ucx_wpool_finalize(opal_common_ucx_wpool_t *wpool)
{
    ucp_cleanup(wpool->ucp_ctx);

    /* Go over the list */
    if (!opal_list_is_empty(&wpool->idle_workers)) {
        _idle_list_item_t *curr_worker, *next;
        OPAL_LIST_FOREACH_SAFE(curr_worker, next, &idle_workers, _idle_list_item_t) {
            opal_list_remove_item(&idle_workers, &curr_worker->super);
            cleanup_worker_tlocal(curr_worker);
            OBJ_RELEASE(curr_worker);
        }
    }
    OBJ_RELEASE(wpool->idle_workers);
}

// TODO: refine the argument lists
typedef int (*opal_common_ucx_allgather_func_t)();
typedef int (*opal_common_ucx_allgatherv_func_t)();

opal_common_ucx_ctx_t *opal_common_ucx_ctx_create(opal_common_ucx_wpool_t *wpool,
                                                  opal_common_ucx_allgather_func_t allgather,
                                                  opal_common_ucx_allgatherv_func_t allgatherv)
{
    opal_common_ucx_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->ctx_id = OPAL_ATOMIC_ADD_FETCH32(&ctx->ctx_id,1);
    OBJ_CONSTRUCT(&ctx->mutex, opal_mutex_t);
    ctx->rcv_worker_addrs = NULL;
    ctx->rcv_worker_displs = NULL;
    ctx->wpool = wpool;
    OBJ_CONSTRUCT(ctx->workers, opal_list_t);
    // Allgather to collect address info
}

int opal_common_ucx_ctx_release(opal_common_ucx_ctx_t *ctx)
{
    // For each element in workers list we need to cleanup a thread-local storage
}

opal_common_ucx_mem_t *opal_common_ucx_mem_create(opal_common_ucx_ctx_t *ctx,
                                                  opal_common_ucx_allgather_func_t allgather,
                                                  opal_common_ucx_allgatherv_func_t allgatherv)
{
    opal_common_ucx_mem_t *mem = calloc(1, sizeof(*mem));
    mem->mem_id = OPAL_ATOMIC_ADD_FETCH32(&ctx->mem_id,1);
    mem->mem_addrs = NULL;
    mem->mem_displs = NULL;
    mem->ctx = ctx;
    OBJ_CONSTRUCT(&ctx->mutex, opal_mutex_t);
    // Allgather to collect address info
}


int opal_common_ucx_mem_release(opal_common_ucx_mem_t *mem)
{
    // 1. Cleanup all thread-local tables assosiated with this mem region
    FOREACH(mem->mem_regions) {
        // dequeue item from the mem->mem_regions list
        // 1. destroy all the rkeys
        // 2. Free mem_info object
        // memory store barrier
        // 3. set mem_id to 0
    }
    // Undo all the initialization steps

}



static int _tlocal_extend_ctxtbl(_thr_local_table *tbl, size_t newsize)
{
    size_t i;
    tbl->ctx_tbl = realloc(tbl->ctx_tbl, newsize * sizeof(*tbl->ctx_tbl));
    for(i = tbl->ctx_tbl_size; i < newsize; i++){
        tbl->ctx_tbl[i] = calloc(1, sizeof(_thr_local_cctx_t));
        // TODO: error checl
    }
    tbl->ctx_tbl_size = newsize;
}

static int _tlocal_extend_memtbl(_thr_local_table *tbl, size_t newsize)
{
    // TODO: Same as ctxtbl
/*
    size_t i;
    tbl->ctx_tbl = realloc(tbl->ctx_tbl, newsize * sizeof(*tbl->ctx_tbl));
    for(i = tbl->ctx_tbl_size; i < newsize; i++){
        tbl->ctx_tbl[i] = calloc(1, sizeof(_thr_local_cctx_t));
    }
    tbl->ctx_tbl_size = newsize;
*/
}


int opal_common_ucx_mem_op(opal_common_ucx_mem_t *mem, opal_common_ucx_op_t op,
                       int target, void *buffer, size_t len, uint64_t rem_addr)
{
     _thr_local_table *tbl = NULL;
    _worker_engine_t *worker_info;
    _mem_info_t *mem_info;
    ucp_ep_h ep;
    ucp_rkey_h rkey;

    if( UNLIKELY((tbl = pthread_get_specific(_tlocal_key)) == NULL) ) {
        tbl = calloc(1, sizeof(*tbl));
        pthread_set_specific(_tlocal_key, tbl);
        if( _tlocal_extend_ctxtbl(tbl, 4) ){
            // TODO: handle error
        }
        if(_tlocal_extend_memtbl(tbl, 4)) {
            // TODO: handle error
        }
    }

    /* Obtain the worker structure */
    if( UNLIKELY((worker_info = _tlocal_search_cctx(mem->ctx->ctx_id)) == NULL ) ) {
        // 1. find the vacant entry or extend.
        // if vacant entry found, after comparing to 0 do a memory barrier.
        // 2. Create/init a worker info
        // 3. Enqueue it into the active list
    }

    /* Obtain the endpoint */
    if( UNLIKELY( NULL == worker_info->endpoints[target])){
        // Create the endpoint

    }
    ep = worker_info->endpoints[target];

    if( UNLIKELY((mem_info = _tlocal_search_mem(mem->mem_id)) == NULL ) ) {
        // 1. find the vacant entry or extend.
        // 2. Create/init a mem info
        // 3. Enqueue it into the mem window struct
    }

    if( UNLIKELY( NULL == mem_info->rkeys[target])){
        // Create the rkey
    }
    rkey = mem_info->rkeys[target];

    opal_mutex_lock(worker_info->mutex);
    switch(op){
    case OPAL_COMMON_UCX_GET:
        status = ucp_put_nbi(ep, buffer,len, rem_addr, rkey);
        if (status != UCS_OK && status != UCS_INPROGRESS) {
            OSC_UCX_VERBOSE(1, "ucp_put_nbi failed: %d", status);
            return OMPI_ERROR;
        }
        break;
    case OPAL_COMMON_UCX_PUT:
        // TODO: fill it
    }
    opal_mutex_unlock(worker_info->mutex);

}


int opal_common_ucx_mem_flush(opal_common_ucx_mem_t *mem,
                              opal_common_ucx_flush_scope_t scope,
                              int target)
{
    opal_mutex_lock(&mem->ctx->mutex);
    FOREACH(mem->ctx->workers) {
        // 1. lock the worker
        // 2. do scope-base work
        // 3. unlock the worker
    }
    opal_mutex_unlock(&mem->ctx->mutex);
}
// ----------------------------------------------


static inline int opal_common_ucx_create_local_worker(ucp_context_h context, int comm_size,
                                                      char *worker_buf, int *worker_disps,
                                                      char *mem_buf, int *mem_disps)
{
    ucp_worker_params_t worker_params;
    ucs_status_t status;
    thread_local_info_t *my_thread_info;
    int i, ret = OPAL_SUCCESS;

    if (!opal_list_is_empty(&idle_workers)) {
        pthread_mutex_lock(&idle_workers_mutex);
        my_thread_info = (thread_local_info_t *)opal_list_get_first(&idle_workers);
        opal_list_remove_item(&idle_workers, &my_thread_info->super);
        pthread_mutex_unlock(&idle_workers_mutex);
    } else {
        my_thread_info = OBJ_NEW(thread_local_info_t);
        memset(my_thread_info, 0, sizeof(thread_local_info_t));
        pthread_mutex_init(&(my_thread_info->lock), NULL);

        my_thread_info->comm_size = comm_size;

        memset(&worker_params, 0, sizeof(worker_params));
        worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
        worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
        status = ucp_worker_create(context, &worker_params,
                                   &(my_thread_info->worker));
        if (UCS_OK != status) {
            ret = OPAL_ERROR;
        }

        my_thread_info->eps = calloc(comm_size, sizeof(ucp_ep_h));
        my_thread_info->rkeys = calloc(comm_size, sizeof(ucp_rkey_h));

        for (i = 0; i < comm_size; i++) {
            ucp_ep_params_t ep_params;

            memset(&ep_params, 0, sizeof(ucp_ep_params_t));
            ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
            ep_params.address = (ucp_address_t *)&(worker_buf[worker_disps[i]]);
            status = ucp_ep_create(my_thread_info->worker, &ep_params,
                                   &my_thread_info->eps[i]);
            if (status != UCS_OK) {
                ret = OPAL_ERROR;
            }

            status = ucp_ep_rkey_unpack(my_thread_info->eps[i],
                                        &(mem_buf[mem_disps[i] + 3 * sizeof(uint64_t)]),
                                        &(my_thread_info->rkeys[i]));
            if (status != UCS_OK) {
                ret = OPAL_ERROR;
            }
        }
    }

    pthread_mutex_lock(&active_workers_mutex);
    opal_list_append(&active_workers, &my_thread_info->super);
    pthread_mutex_unlock(&active_workers_mutex);

    pthread_setspecific(my_thread_key, my_thread_info);

    return ret;
}
