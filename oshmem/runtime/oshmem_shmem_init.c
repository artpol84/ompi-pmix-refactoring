/*
 * Copyright (c) 2013      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * Copyright (c) 2015-2016 Research Organization for Information Science
 *                         and Technology (RIST). All rights reserved.
 * Copyright (c) 2015      Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "oshmem_config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif  /* HAVE_SYS_TIME_H */
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <float.h>

#include "math.h"
#include "opal/class/opal_list.h"
#include "opal/mca/base/base.h"
#include "opal/runtime/opal_progress.h"
#include "opal/threads/threads.h"
#include "opal/util/argv.h"
#include "opal/util/output.h"
#include "opal/util/error.h"
#include "opal/util/stacktrace.h"
#include "opal/util/show_help.h"
#include "opal/runtime/opal.h"

#include "orte/util/proc_info.h"
#include "orte/runtime/runtime.h"
#include "orte/mca/grpcomm/grpcomm.h"
#include "orte/runtime/orte_globals.h"
#include "orte/util/show_help.h"
#include "orte/mca/ess/ess.h"
#include "orte/runtime/orte_globals.h"
#include "orte/mca/errmgr/errmgr.h"
#include "orte/util/name_fns.h"

#include "ompi/datatype/ompi_datatype.h"
#include "opal/mca/rcache/base/base.h"
#include "opal/mca/mpool/base/base.h"
#include "opal/mca/allocator/base/base.h"
#include "ompi/proc/proc.h"
#include "ompi/runtime/mpiruntime.h"

#include "oshmem/constants.h"
#include "oshmem/runtime/runtime.h"
#include "oshmem/runtime/params.h"
#include "oshmem/runtime/oshmem_shmem_preconnect.h"
#include "oshmem/mca/spml/base/base.h"
#include "oshmem/mca/scoll/base/base.h"
#include "oshmem/mca/atomic/base/base.h"
#include "oshmem/mca/memheap/base/base.h"
#include "oshmem/mca/sshmem/base/base.h"
#include "oshmem/info/info.h"
#include "oshmem/proc/proc.h"
#include "oshmem/proc/proc_group_cache.h"
#include "oshmem/op/op.h"
#include "oshmem/request/request.h"
#include "oshmem/shmem/shmem_api_logger.h"

#include "oshmem/shmem/shmem_lock.h"

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#if OPAL_CC_USE_PRAGMA_IDENT
#pragma ident OMPI_IDENT_STRING
#elif OPAL_CC_USE_IDENT
#ident OSHMEM_IDENT_STRING
#endif

/*
 * WHAT: add thread for invoking opal_progress() function
 * WHY:  SHMEM based on current ompi/trunk (by the time of integrating into Open MPI)
 *       has put/get implementation via send and needs opal_progress() invocation
 *       on the remote side (i.e. not true one-sided operations).
 */
#define OSHMEM_OPAL_THREAD_ENABLE 0

const char oshmem_version_string[] = OSHMEM_IDENT_STRING;

/*
 * Global variables and symbols for the MPI layer
 */

bool oshmem_shmem_initialized = false;
bool oshmem_shmem_aborted = false;
bool oshmem_mpi_thread_multiple = false;
int oshmem_mpi_thread_requested = SHMEM_THREAD_SINGLE;
int oshmem_mpi_thread_provided = SHMEM_THREAD_SINGLE;
long *preconnect_value = 0;
int shmem_api_logger_output = -1;

MPI_Comm oshmem_comm_world = {0};

opal_thread_t *oshmem_mpi_main_thread = NULL;

static int _shmem_init(int argc, char **argv, int requested, int *provided);

#if OSHMEM_OPAL_THREAD_ENABLE
static void* shmem_opal_thread(void* argc)
{
/*
 * WHAT: sleep() invocation
 * WHY:  there occures a segfault sometimes and sleep()
 *       reduces it's possibility
 */
    sleep(1);
    while(oshmem_shmem_initialized)
        opal_progress();
    return NULL;
}
#endif

int oshmem_shmem_inglobalexit = 0;
int oshmem_shmem_globalexit_status = -1;

static void sighandler__SIGUSR1(int signum)
{
    if (0 != oshmem_shmem_inglobalexit)
    {
	return;
    }
    _exit(0);
}
static void sighandler__SIGTERM(int signum)
{
    /* Do nothing. Just replace other unpredictalbe handlers with this one (e.g. mxm handler). */
}

#include <time.h>
#define GET_TS ({ \
    struct timespec ts;                     \
    double ret;                             \
    clock_gettime(CLOCK_MONOTONIC, &ts);    \
    ret = ts.tv_sec + 1E-9 * ts.tv_nsec;    \
    ret;                                    \
})


int oshmem_shmem_init(int argc, char **argv, int requested, int *provided)
{
    int ret = OSHMEM_SUCCESS;

    if (!oshmem_shmem_initialized) {
        if (!ompi_mpi_initialized && !ompi_mpi_finalized) {
            ret = ompi_mpi_init(argc, argv, requested, provided);
        }

        if (OSHMEM_SUCCESS != ret) {
            return ret;
        }
        
        int rank, size, delay = 0;
        MPI_Comm_rank(MPI_COMM_WORLD, &rank);
        MPI_Comm_size(MPI_COMM_WORLD, &size);
        while( (rank == 0 ) && delay ) {
            sleep(1);
        }

        double ts;
        double in[2], out1[2], out2[2], out3[2];

        ts = GET_TS;
        PMPI_Comm_dup(MPI_COMM_WORLD, &oshmem_comm_world);
        in[0] = GET_TS - ts;
        
        ts = GET_TS;
        ret = _shmem_init(argc, argv, requested, provided);
        in[1] = GET_TS - ts;
        
        MPI_Reduce(in, out1, 2, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
        MPI_Reduce(in, out2, 2, MPI_DOUBLE, MPI_MIN, 0, MPI_COMM_WORLD);
        MPI_Reduce(in, out3, 2, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

        if( rank == 0 ){
            out1[0] /= size;
            out1[1] /= size;
            printf("PMPI_Comm_dup(MPI_COMM_WORLD, &oshmem_comm_world): %lf/%lf/%lf\n",
                    out2[0], out3[0], out1[0] );
            printf("_shmem_init(argc, argv, requested, provided): %lf/%lf/%lf\n",
                    out2[1], out3[1], out1[1]);
        }
        
        if (OSHMEM_SUCCESS != ret) {
            return ret;
        }
        oshmem_shmem_initialized = true;

        if (OSHMEM_SUCCESS != shmem_lock_init()) {
            SHMEM_API_ERROR( "shmem_lock_init() failed");
            return OSHMEM_ERROR;
        }

        /* this is a collective op, implies barrier */
        MCA_MEMHEAP_CALL(get_all_mkeys());

        oshmem_shmem_preconnect_all();
#if OSHMEM_OPAL_THREAD_ENABLE
        pthread_t thread_id;
        int perr;
        perr = pthread_create(&thread_id, NULL, &shmem_opal_thread, NULL);
        if (0 != perr) {
            SHMEM_API_ERROR("cannot create opal thread for SHMEM");
            return OSHMEM_ERROR;
        }
#endif
    }
#ifdef SIGUSR1
    signal(SIGUSR1,sighandler__SIGUSR1);
    signal(SIGTERM,sighandler__SIGTERM);
#endif
    return ret;
}

int oshmem_shmem_preconnect_all(void)
{
    int rc = OSHMEM_SUCCESS;

    /* force qp creation and rkey exchange for memheap. Does not force exchange of static vars */
    if (oshmem_preconnect_all) {
        long val;
        int nproc;
        int my_pe;
        int i;

        val = 0xdeadbeaf;

        if (!preconnect_value) {
            rc =
                    MCA_MEMHEAP_CALL(private_alloc(sizeof(long), (void **)&preconnect_value));
        }
        if (!preconnect_value || (rc != OSHMEM_SUCCESS)) {
            SHMEM_API_ERROR("shmem_preconnect_all failed");
            return OSHMEM_ERR_OUT_OF_RESOURCE;
        }

        nproc = oshmem_num_procs();
        my_pe = oshmem_my_proc_id();
        for (i = 0; i < nproc; i++) {
            shmem_long_p(preconnect_value, val, (my_pe + i) % nproc);
        }
        shmem_barrier_all();
        SHMEM_API_VERBOSE(5, "Preconnected all PEs");
    }

    return OSHMEM_SUCCESS;
}

int oshmem_shmem_preconnect_all_finalize(void)
{
    if (preconnect_value) {
        MCA_MEMHEAP_CALL(private_free(preconnect_value));
        preconnect_value = 0;
    }

    return OSHMEM_SUCCESS;
}

static int _shmem_init(int argc, char **argv, int requested, int *provided)
{
    int ret = OSHMEM_SUCCESS;
    char *error = NULL;
    char *data_descr[1024];
    double ts, data[1024];
    int data_cnt = 0;

    ts = GET_TS;
    /* Register the OSHMEM layer's MCA parameters */
    if (OSHMEM_SUCCESS != (ret = oshmem_shmem_register_params())) {
        error = "oshmem_info_register: oshmem_register_params failed";
        goto error;
    }
    data_descr[data_cnt] = "oshmem_shmem_register_params";
    data[data_cnt++] = GET_TS - ts;
    
    /* Setting verbosity for macros like SHMEM_API_VERBOSE, SHMEM_API_ERROR.
     * We need to set it right after registering mca verbosity variables
     */

    ts = GET_TS;
    shmem_api_logger_output = opal_output_open(NULL);
    opal_output_set_verbosity(shmem_api_logger_output,
                              oshmem_shmem_api_verbose);
    data_descr[data_cnt] = "opal_output_open";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;


    /* initialize info */
    if (OSHMEM_SUCCESS != (ret = oshmem_info_init())) {
        error = "oshmem_info_init() failed";
        goto error;
    }

    data_descr[data_cnt] = "oshmem_info_init";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    /* initialize proc */
    if (OSHMEM_SUCCESS != (ret = oshmem_proc_init())) {
        error = "oshmem_proc_init() failed";
        goto error;
    }

    data_descr[data_cnt] = "oshmem_proc_init";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = oshmem_group_cache_list_init())) {
        error = "oshmem_group_cache_list_init() failed";
        goto error;
    }

    data_descr[data_cnt] = "oshmem_group_cache_list_init";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = oshmem_op_init())) {
        error = "oshmem_op_init() failed";
        goto error;
    }

    data_descr[data_cnt] = "oshmem_op_init";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;
    

    if (OSHMEM_SUCCESS != (ret = mca_base_framework_open(&oshmem_spml_base_framework, MCA_BASE_OPEN_DEFAULT))) {
        error = "mca_spml_base_open() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_base_framework_open(&oshmem_spml_base_framework)";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = mca_base_framework_open(&oshmem_scoll_base_framework, MCA_BASE_OPEN_DEFAULT))) {
        error = "mca_scoll_base_open() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_base_framework_open(&oshmem_scoll_base_framework)";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;


    if (OSHMEM_SUCCESS
            != (ret = mca_spml_base_select(OPAL_ENABLE_PROGRESS_THREADS,
                                           OMPI_ENABLE_THREAD_MULTIPLE))) {
        error = "mca_spml_base_select() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_spml_base_select";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS
            != (ret =
                    mca_scoll_base_find_available(OPAL_ENABLE_PROGRESS_THREADS,
                                                  OMPI_ENABLE_THREAD_MULTIPLE))) {
        error = "mca_scoll_base_find_available() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_scoll_base_find_available";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    /* Initialize each SHMEM handle subsystem */
    /* Initialize requests */
    if (OSHMEM_SUCCESS != (ret = oshmem_request_init())) {
        error = "oshmem_request_init() failed";
        goto error;
    }

    data_descr[data_cnt] = "oshmem_request_init";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = oshmem_proc_group_init())) {
        error = "oshmem_proc_group_init() failed";
        goto error;
    }

    data_descr[data_cnt] = "oshmem_proc_group_init";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    /* start SPML/BTL's */
    ret = MCA_SPML_CALL(enable(true));
    if (OSHMEM_SUCCESS != ret) {
        error = "SPML control failed";
        goto error;
    }

    data_descr[data_cnt] = "MCA_SPML_CALL(enable(true))";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    ret =
            MCA_SPML_CALL(add_procs(oshmem_group_all->proc_array, oshmem_group_all->proc_count));
    if (OSHMEM_SUCCESS != ret) {
        error = "SPML add procs failed";
        goto error;
    }

    data_descr[data_cnt] = "MCA_SPML_CALL(add_procs)";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = mca_base_framework_open(&oshmem_sshmem_base_framework, MCA_BASE_OPEN_DEFAULT))) {
        error = "mca_sshmem_base_open() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_base_framework_open(&oshmem_sshmem_base_framework)";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = mca_sshmem_base_select())) {
        error = "mca_sshmem_base_select() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_sshmem_base_select";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = mca_base_framework_open(&oshmem_memheap_base_framework, MCA_BASE_OPEN_DEFAULT))) {
        error = "mca_memheap_base_open() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_base_framework_open(&oshmem_memheap_base_framework)";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = mca_memheap_base_select())) {
        error = "mca_memheap_base_select() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_memheap_base_select";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS != (ret = mca_base_framework_open(&oshmem_atomic_base_framework, MCA_BASE_OPEN_DEFAULT))) {
        error = "mca_atomic_base_open() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_base_framework_open(&oshmem_atomic_base_framework)";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    if (OSHMEM_SUCCESS
            != (ret =
                    mca_atomic_base_find_available(OPAL_ENABLE_PROGRESS_THREADS,
                                                   OMPI_ENABLE_THREAD_MULTIPLE))) {
        error = "mca_atomic_base_find_available() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_atomic_base_find_available";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;

    /* This call should be done after memheap initialization */
    if (OSHMEM_SUCCESS != (ret = mca_scoll_enable())) {
        error = "mca_scoll_enable() failed";
        goto error;
    }

    data_descr[data_cnt] = "mca_scoll_enable";
    data[data_cnt++] = GET_TS - ts;
    ts = GET_TS;
    
    {
        int rank, size, i;
        double max[data_cnt], min[data_cnt], sum[data_cnt];
        MPI_Comm_size(MPI_COMM_WORLD, &size);
        MPI_Comm_rank(MPI_COMM_WORLD, &rank);
        
        MPI_Reduce(data, max, data_cnt, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
        MPI_Reduce(data, min, data_cnt, MPI_DOUBLE, MPI_MIN, 0, MPI_COMM_WORLD);
        MPI_Reduce(data, sum, data_cnt, MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD);
        
        if( rank == 0 ){
            printf("------------ _smem_init timing: -----------------\n");
            for(i=0; i<data_cnt; i++){
                printf("\t%s: %lf / %lf / %lf\n",
                            data_descr[i], sum[i]/size, min[i], max[i]);
            }
            printf("------------                    -----------------\n");
        }
    
    }

    error:
     if (ret != OSHMEM_SUCCESS) {
        const char *err_msg = opal_strerror(ret);
        orte_show_help("help-shmem-runtime.txt",
                       "shmem_init:startup:internal-failure",
                       true,
                       "SHMEM_INIT",
                       "SHMEM_INIT",
                       error,
                       err_msg,
                       ret);
        return ret;
    }

    return ret;
}

