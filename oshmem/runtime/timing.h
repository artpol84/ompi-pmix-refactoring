#ifndef OSHTMNG_TIMING_H
#define OSHTMNG_TIMING_H

#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "oshmem_config.h"

#include "oshmem/constants.h"
#include "oshmem/runtime/runtime.h"
#include "oshmem/runtime/params.h"

static inline double OSHTMNG_GET_TS(void)
{
    struct timespec ts;
    double ret;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ret = ts.tv_sec + 1E-9 * ts.tv_nsec;
    return ret;
}

#define OSHTMNG_INIT(inum)                              \
        double OSHTMNG_ts;                              \
        const char *OSHTMNG_prefix = __FUNCTION__;      \
        int OSHTMNG_cnt = 0;                            \
        int OSHTMNG_inum = inum;                        \
        double OSHTMNG_in[inum]  = { 0.0 };             \
        double OSHTMNG_max[inum] = { 0.0 };             \
        double OSHTMNG_min[inum] = { 0.0 };             \
        double OSHTMNG_avg[inum] = { 0.0 };             \
        char *OSHTMNG_desc[inum] = { 0 };

#define OSHTMNG_START {                     \
    OSHTMNG_ts = OSHTMNG_GET_TS();            \
}

#define OSHTMNG_END(desc) {                                       \
    char *ptr = strrchr(__FILE__, '/');                           \
    if( NULL == ptr ){                                            \
        ptr = __FILE__;                                           \
    } else {                                                      \
        ptr++;                                                    \
    }                                                             \
    if( OSHTMNG_inum <= OSHTMNG_cnt ){                            \
        printf("OSHTMNG [%s:%d %s]: interval count overflow!!\n", \
            ptr, __LINE__, __FUNCTION__);                         \
        abort();                                                  \
    }                                                             \
    OSHTMNG_in[OSHTMNG_cnt] =    OSHTMNG_GET_TS() - OSHTMNG_ts;   \
    OSHTMNG_desc[OSHTMNG_cnt++] = desc;                           \
    OSHTMNG_ts = OSHTMNG_GET_TS();                                \
}

#define OSHTMNG_OUT {                                                   \
    int i, size, rank;                                                  \
    MPI_Comm_size(MPI_COMM_WORLD, &size);                               \
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);                               \
    char ename[1024];                                                   \
    sprintf(ename, "OSHTMNG_%s", OSHTMNG_prefix);                       \
    char *ptr = getenv(ename);                                          \
                                                                        \
    if( NULL != ptr ) {                                                 \
        OSHTMNG_ts = OSHTMNG_GET_TS();                                  \
        MPI_Reduce(OSHTMNG_in, OSHTMNG_avg, OSHTMNG_cnt, MPI_DOUBLE,    \
                    MPI_SUM, 0, MPI_COMM_WORLD);                        \
        MPI_Reduce(OSHTMNG_in, OSHTMNG_min, OSHTMNG_cnt, MPI_DOUBLE,    \
                    MPI_MIN, 0, MPI_COMM_WORLD);                        \
        MPI_Reduce(OSHTMNG_in, OSHTMNG_max, OSHTMNG_cnt, MPI_DOUBLE,    \
                    MPI_MAX, 0, MPI_COMM_WORLD);                        \
                                                                        \
        if( 0 == rank ){                                                \
            printf("------------------ %s ------------------\n",        \
                    OSHTMNG_prefix);                                    \
            for(i=0; i< OSHTMNG_cnt; i++){                              \
                OSHTMNG_avg[i] /= size;                                 \
                printf("[%s:%s]: %lf / %lf / %lf\n",                    \
                    OSHTMNG_prefix,OSHTMNG_desc[i],                     \
                    OSHTMNG_avg[i], OSHTMNG_min[i], OSHTMNG_max[i]);    \
            }                                                           \
            printf("[%s:overhead]: %lf \n", OSHTMNG_prefix,             \
                    OSHTMNG_GET_TS() - OSHTMNG_ts);                     \
        }                                                               \
    }                                                                   \
}

#endif