typedef unsigned long uint64;

uint64 str_hash(char *str) {
    uint64 hash = 5381;
    int c;
    uint64 cycles = 0;
    while (c = *str++) {
        /* hash * 33 + c */
        hash = ((hash << 5) + hash) + c;
        // 限制最大循环次数
        // if (++cycles >= 0x20) break;
    }
    return hash;
}
