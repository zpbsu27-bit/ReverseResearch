package demo;

// Static producer fixture: no main, Activity, device or executable entry point.
public final class OfflineCodeProbe {
    public static final int[] VALUES = {7, 11, 13, 17, 19};
    public static int dense(int value) {
        switch (value) {
            case -1: return 7;
            case 0: return 11;
            case 1: return 13;
            case 2: return 17;
            case 3: return 19;
            case 4: return 23;
            case 5: return 29;
            case 6: return 31;
            case 7: return 37;
            default: return value * 3;
        }
    }
    public static int sparse(int value) {
        switch (value) {
            case -9: return 17;
            case 1001: return 19;
            case 100001: return 23;
            case 123456: return 29;
            case 234567: return 31;
            case 345678: return 37;
            case 456789: return 41;
            case 567890: return 43;
            case 678901: return 47;
            default: return -value;
        }
    }
    public static int array(int index) {
        int[] values = {7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67};
        return values[index];
    }
    public static long wide(long value) {
        return (value ^ 0x8000000000000123L) + 0x123456789L;
    }
    public static int guarded(String value) {
        try {
            return value.length();
        } catch (NullPointerException failure) {
            return failure.getMessage() == null ? -1 : -2;
        }
    }
    public static int overload(int value) { return value + 7; }
    public static String overload(String value) { return value + "!"; }
    public static int callProbe(int value) { return dense(value) + sparse(value); }
    public static native void nativeProbe();
}
