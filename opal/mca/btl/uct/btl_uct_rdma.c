/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2014-2018 Los Alamos National Security, LLC. All rights
 *                         reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "btl_uct_rdma.h"

void mca_btl_uct_uct_completion (uct_completion_t *uct_comp, ucs_status_t status)
{
    mca_btl_uct_uct_completion_t *comp = (mca_btl_uct_uct_completion_t *) uct_comp;
    /* we may be calling the callback before remote completion. this is in violation of the
     * btl interface specification but should not hurt in non-ob1 use cases. if this ever
     * becomes a problem we can look at possible solutions. */
    comp->cbfunc (comp->btl, comp->endpoint, comp->local_address, comp->local_handle,
                  comp->cbcontext, comp->cbdata, UCS_OK == status ? OPAL_SUCCESS : OPAL_ERROR);
    mca_btl_uct_uct_completion_release (comp);
}

mca_btl_uct_uct_completion_t *mca_btl_uct_uct_completion_alloc (mca_btl_base_module_t *btl, mca_btl_base_endpoint_t *endpoint,
                                                                void *local_address, mca_btl_base_registration_handle_t *local_handle,
                                                                mca_btl_base_rdma_completion_fn_t cbfunc,
                                                                void *cbcontext, void *cbdata)
{
    mca_btl_uct_uct_completion_t *comp = malloc (sizeof (*comp));

    comp->uct_comp.func = mca_btl_uct_uct_completion;
    comp->uct_comp.count = 1;
    comp->btl = btl;
    comp->endpoint = endpoint;
    comp->local_address = local_address;
    comp->local_handle = local_handle;
    comp->cbfunc = cbfunc;
    comp->cbcontext = cbcontext;
    comp->cbdata = cbdata;

    return comp;
}

void mca_btl_uct_uct_completion_release (mca_btl_uct_uct_completion_t *comp)
{
    free (comp);
}

int mca_btl_uct_get (mca_btl_base_module_t *btl, mca_btl_base_endpoint_t *endpoint, void *local_address,
                      uint64_t remote_address, mca_btl_base_registration_handle_t *local_handle,
                      mca_btl_base_registration_handle_t *remote_handle, size_t size, int flags,
                      int order, mca_btl_base_rdma_completion_fn_t cbfunc, void *cbcontext, void *cbdata)
{
    uct_iov_t iov = {.buffer = local_address, .length = size, .stride = 0, .count = 1,
                     .memh = MCA_BTL_UCT_REG_REMOTE_TO_LOCAL(local_handle)->uct_memh};
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) btl;
    mca_btl_uct_device_context_t *context = mca_btl_uct_module_get_context (uct_module);
    mca_btl_uct_uct_completion_t *comp = NULL;
    ucs_status_t ucs_status;
    uct_rkey_bundle_t rkey;
    uct_ep_h ep_handle;
    int rc;

    if (cbfunc) {
        comp = mca_btl_uct_uct_completion_alloc (btl, endpoint, local_address, local_handle, cbfunc, cbcontext, cbdata);
        if (OPAL_UNLIKELY(NULL == comp)) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
    }

    rc = mca_btl_uct_get_rkey (uct_module, context, endpoint, remote_handle, &rkey, &ep_handle);
    if (OPAL_UNLIKELY(OPAL_SUCCESS != rc)) {
        mca_btl_uct_uct_completion_release (comp);
        return rc;
    }

    mca_btl_uct_context_lock (context);

    ucs_status = uct_ep_get_zcopy (ep_handle, &iov, 1, remote_address, rkey.rkey, &comp->uct_comp);

    /* go ahead and progress the worker while we have the lock */
    (void) uct_worker_progress (context->uct_worker);

    mca_btl_uct_context_unlock (context);

    if (UCS_OK == ucs_status && cbfunc) {
        /* if UCS_OK is returned the callback will never fire so we have to make the callback
         * ourselves */
        cbfunc (btl, endpoint, local_address, local_handle, cbcontext, cbdata, OPAL_SUCCESS);
        free (comp);
    } else if (UCS_INPROGRESS == ucs_status) {
        ucs_status = UCS_OK;
    }

    uct_rkey_release (&rkey);

    return OPAL_LIKELY(UCS_OK == ucs_status) ? OPAL_SUCCESS : OPAL_ERR_RESOURCE_BUSY;
}

int mca_btl_uct_put (mca_btl_base_module_t *btl, mca_btl_base_endpoint_t *endpoint, void *local_address,
                      uint64_t remote_address, mca_btl_base_registration_handle_t *local_handle,
                      mca_btl_base_registration_handle_t *remote_handle, size_t size, int flags,
                      int order, mca_btl_base_rdma_completion_fn_t cbfunc, void *cbcontext, void *cbdata)
{
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) btl;
    mca_btl_uct_device_context_t *context = mca_btl_uct_module_get_context (uct_module);
    mca_btl_uct_uct_completion_t *comp = NULL;
    ucs_status_t ucs_status;
    uct_rkey_bundle_t rkey;
    uct_ep_h ep_handle;
    int rc;

    printf("mca_btl_uct_put: %d\n", (context - uct_module->contexts));

    if (size >  uct_module->super.btl_put_local_registration_threshold && cbfunc) {
        comp = mca_btl_uct_uct_completion_alloc (btl, endpoint, local_address, local_handle, cbfunc, cbcontext, cbdata);
        if (OPAL_UNLIKELY(NULL == comp)) {
            return OPAL_ERR_OUT_OF_RESOURCE;
        }
    }

    rc = mca_btl_uct_get_rkey (uct_module, context, endpoint, remote_handle, &rkey, &ep_handle);
    if (OPAL_UNLIKELY(OPAL_SUCCESS != rc)) {
        mca_btl_uct_uct_completion_release (comp);
        return rc;
    }

    mca_btl_uct_context_lock (context);

    if (size > uct_module->super.btl_put_local_registration_threshold) {
        uct_iov_t iov = {.buffer = local_address, .length = size, .stride = 0, .count = 1,
                         .memh = MCA_BTL_UCT_REG_REMOTE_TO_LOCAL(local_handle)->uct_memh};

        ucs_status = uct_ep_put_zcopy (ep_handle, &iov, 1, remote_address, rkey.rkey, &comp->uct_comp);
    } else {
        ucs_status = uct_ep_put_short (ep_handle, local_address, size, remote_address, rkey.rkey);
    }

    /* go ahead and progress the worker while we have the lock */
    (void) uct_worker_progress (context->uct_worker);

    mca_btl_uct_context_unlock (context);

    if (UCS_OK == ucs_status && cbfunc) {
        /* if UCS_OK is returned the callback will never fire so we have to make the callback
         * ourselves. this callback is possibly being made before the data is visible to the
         * remote process. */
        cbfunc (btl, endpoint, local_address, local_handle, cbcontext, cbdata, OPAL_SUCCESS);
        free (comp);
    } else if (UCS_INPROGRESS == ucs_status) {
        ucs_status = UCS_OK;
    }

    uct_rkey_release (&rkey);

    return OPAL_LIKELY(UCS_OK == ucs_status) ? OPAL_SUCCESS : OPAL_ERR_RESOURCE_BUSY;
}

int mca_btl_uct_flush (mca_btl_base_module_t *btl, mca_btl_base_endpoint_t *endpoint)
{
    mca_btl_uct_module_t *uct_module = (mca_btl_uct_module_t *) btl;
    ucs_status_t ucs_status;

    /* flush all device contexts */
    for (int i = 0 ; i < uct_module->uct_worker_count ; ++i) {
        mca_btl_uct_device_context_t *context = uct_module->contexts + i;

        if (NULL == context->uct_worker) {
            continue;
        }

        mca_btl_uct_context_lock (context);
        /* this loop is here because at least some of the TLs do no support a
         * completion callback. its a real PIA but has to be done for now. */
        do {
            uct_worker_progress (context->uct_worker);

            if (NULL != endpoint && endpoint->uct_eps[i]) {
                ucs_status = uct_ep_flush (endpoint->uct_eps[i], 0, NULL);
            } else {
                ucs_status = uct_iface_flush (context->uct_iface, 0, NULL);
            }
        } while (UCS_INPROGRESS == ucs_status);

        mca_btl_uct_context_unlock (context);
    }

    return UCS_OK == ucs_status ? OPAL_SUCCESS : OPAL_ERR_RESOURCE_BUSY;
}
