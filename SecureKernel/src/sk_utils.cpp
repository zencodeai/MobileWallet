#include "sk_utils.hpp"

#include <sys/time.h>

// Get timestamp
uint64_t SKUtils::GetTimestamp() {

    // Get time
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Return timestamp
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}
