#define _GNU_SOURCE
#include <time.h>
#include <dlfcn.h>
#include <stdlib.h>
// Freeze only CLOCK_REALTIME. Scheduler/deadline clocks still advance.
int clock_gettime(clockid_t clock, struct timespec *result) {
    static int (*real_clock_gettime)(clockid_t, struct timespec *);
    if (!real_clock_gettime) real_clock_gettime=dlsym(RTLD_NEXT,"clock_gettime");
    const char *value=getenv("BETTER_AUTH_PROOF_CLOCK_MS");
    if (clock==CLOCK_REALTIME && value) {
        long long millis=strtoll(value,0,10);
        result->tv_sec=millis/1000;result->tv_nsec=(millis%1000)*1000000;
        return 0;
    }
    return real_clock_gettime(clock,result);
}
