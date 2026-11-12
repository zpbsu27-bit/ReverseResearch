/* Owned, harmless static-analysis fixture. Compile twice with RR_OFFSET=1/2.
 * The research smoke never executes either produced target. */
#ifndef RR_OFFSET
#define RR_OFFSET 1
#endif

__declspec(dllexport) __attribute__((noinline))
int rr_calculate(int value) {
    return value * 3 + RR_OFFSET;
}

int main(void) {
    return rr_calculate(7);
}
