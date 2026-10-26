package demo.service;

public class Grades {
    /** Round the overall mean of a student to the nearest whole number, halves go up. */
    public static int roundedMean(double[] marks) {
        double sum = 0;
        for (double m : marks) {
            sum += m;
        }
        double mean = sum / marks.length;
        return (int) Math.floor(mean + 0.5);
    }

    /** A student passes when the mean reaches the pass mark. */
    public static boolean passes(double mean, double passMark) {
        if (mean >= passMark) {
            return true;
        }
        return false;
    }
}
