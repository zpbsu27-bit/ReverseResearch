package rrfixture;

// Source-owned compiler fixture. It has no main and is never run or installed.
public final class OfflineProbe {
    private final int value;
    public static final String TEXT = "probe:\u0000\uD83D\uDE00";

    public OfflineProbe(int value) {
        this.value = value;
    }

    public int compute(int divisor) {
        try {
            return value * 3 / divisor;
        } catch (ArithmeticException e) {
            return -1;
        }
    }

    public static native int nativeProbe();

    public String describe() {
        return "RR:" + value;
    }
}
