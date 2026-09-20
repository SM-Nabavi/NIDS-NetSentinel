#ifndef NIDS_TIME_COMPAT_H
#define NIDS_TIME_COMPAT_H

#ifdef _WIN32
    #include <windows.h>
    #include <stdint.h>

    static inline int gettimeofday_win(struct timeval *tv, void *tz) {
        (void)tz;
        if (!tv) return -1;

        FILETIME ft;
        uint64_t tmpres = 0;

        GetSystemTimeAsFileTime(&ft);
        tmpres = (uint64_t)ft.dwHighDateTime << 32;
        tmpres |= ft.dwLowDateTime;

        tmpres /= 10ULL;

        tmpres -= 11644473600000000ULL;

        tv->tv_sec = (long)(tmpres / 1000000ULL);
        tv->tv_usec = (long)(tmpres % 1000000ULL);

        return 0;
    }

    #define gettimeofday(tv, tz) gettimeofday_win(tv, tz)

#else
    #include <sys/time.h>
#endif

#endif /* NIDS_TIME_COMPAT_H */