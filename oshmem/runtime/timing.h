#ifndef OSHTMNG_TIMING_H
#define OSHTMNG_TIMING_H

#include <time.h>
#include <string.h>
#include <stdlib.h>

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

#define OSHTMNG_END1(desc,ts) {                                   \
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
    OSHTMNG_in[OSHTMNG_cnt] = ts;                                 \
    OSHTMNG_desc[OSHTMNG_cnt++] = desc;                           \
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

typedef struct {
    char prefix[256], cntr_env[256];
    int enabled;
    int cntr;
    double ts;
} OSHTMNG_ENV_t;

static inline OSHTMNG_ENV_t OSHTMNG_ENV_START(char *env_prefix)
{
{
    int delay = 0;
    while( delay ){
	sleep(1);
    }
}
    OSHTMNG_ENV_t h;
    strcpy(h.prefix, env_prefix);
    sprintf(h.cntr_env,"%s_CNT", h.prefix);
    h.ts = OSHTMNG_GET_TS();
    h.enabled = 1;

    char *ptr = getenv(env_prefix);
    if( NULL == ptr || strcmp(ptr, "1")){
        h.enabled = 0;
    }
    ptr = getenv(h.cntr_env);
    h.cntr = 0;
    if( NULL != ptr ){
        h.cntr = atoi(ptr);
    }
    return h;
}
static inline void OSHTMNG_ENV_NEXT(OSHTMNG_ENV_t *h, char *fmt, ... )
{
    if( !h->enabled ){
        return;
    }
    /* enabled codepath */
    int n;
    va_list ap;
    char buf[256], buf2[256];
    double time = OSHTMNG_GET_TS() - h->ts;

    sprintf(buf, "%s_INT_%d_DESC", h->prefix, h->cntr);
    va_start(ap, fmt);
    n= vsnprintf(buf2, 256, fmt, ap);
    va_end(ap);
    setenv(buf, buf2, 1);

    sprintf(buf, "%s_INT_%d_VAL", h->prefix, h->cntr);
    sprintf(buf2, "%lf", time);
    setenv(buf, buf2, 1);

    h->cntr++;
    sprintf(buf, "%d", h->cntr);
    setenv(h->cntr_env, buf, 1);

    h->ts = OSHTMNG_GET_TS();
}

static inline int OSHTMNG_ENV_COUNT(char *prefix)
{
    char ename[256];
    sprintf(ename, "%s_CNT", prefix);
    char *ptr = getenv(ename);
    if( !ptr ){
        return 0;
    }
    return atoi(ptr);
}

static inline double OSHTMNG_ENV_GETBYIDX(char *prefix, int i, char **desc)
{
    char vname[256];
    double ts;
    sprintf(vname, "%s_INT_%d_DESC", prefix, i);
    *desc = getenv(vname);
    sprintf(vname, "%s_INT_%d_VAL",prefix, i);
    char *ptr = getenv(vname);
    sscanf(ptr,"%lf", &ts);
    return ts;
}

#define OSHTMNG_ENV_APPEND(prefix) {                          \
    char *enabled;                                            \
    int cnt = OSHTMNG_ENV_COUNT(prefix);                      \
    enabled = getenv(prefix);                                 \
    if( NULL != enabled && !strcmp(enabled, "1") )  {         \
        char ename[256];                                      \
        sprintf(ename, "OSHTMNG_%s", OSHTMNG_prefix);         \
        setenv(ename, "1", 1);                                \
    }                                                         \
    int i;                                                    \
    for(i = 0; i < cnt; i++){                                 \
        char *desc;                                           \
        double ts = OSHTMNG_ENV_GETBYIDX(prefix, i, &desc);   \
        OSHTMNG_END1(desc, ts);                               \
    }                                                         \
}

#endif