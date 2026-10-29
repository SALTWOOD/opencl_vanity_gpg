#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// The values below are only used when this file is edited standalone; the
// program replaces the __INJECTS__ line with the actual configuration.
#define __INJECTS__
#ifdef __INJECTS__
#define FUTURE_MODE (0)
#define TOTAL_WORDS (4)
#endif

__kernel void vanity_sha1(__constant uint *hashdata, __global uint *result, const ulong iter, const uint max_time_range) {
    uint data[TOTAL_WORDS];
    for (uint i = 0; i < TOTAL_WORDS; i++) data[i] = hashdata[i];
    uint nonce = data[1];

    uint thread_id = get_global_id(0);

    for (uint i = 0; i < iter; i++) {
        // Use a simple sequential approach that searches close to base time first
        // Each thread gets a small sequential offset
        uint offset = thread_id + i * get_global_size(0);

        // Avoid going too far (within max_time_range)
        if (max_time_range && offset > max_time_range) break;

        uint ts;
        if (FUTURE_MODE) {
            // For future mode: increment timestamp within range
            ts = nonce + offset;
            // Check for overflow
            if (ts < nonce) break;
        } else {
            // For past mode: decrement timestamp within range
            ts = nonce - offset;
            // Check for underflow
            if (ts > nonce) break;
        }

// __TARGET_CHECKS__
    }
}
