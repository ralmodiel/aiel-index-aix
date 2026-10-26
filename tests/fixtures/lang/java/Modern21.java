package demo;

import java.util.List;

public class Modern21 {
    // Java 16 records, 17 sealed types, 21 pattern switch and record patterns, text blocks
    public record Point(int x, int y) {
        public Point {
            if (x < 0) throw new IllegalArgumentException("neg");
        }
        double dist() { return Math.sqrt(x * x + y * y); }
    }

    public sealed interface Shape permits Circle, Square {}
    public record Circle(Point c, int r) implements Shape {}
    public record Square(Point a, int side) implements Shape {}

    static String describe(Object o) {
        return switch (o) {
            case Circle(Point p, int r) when r > 10 -> "big circle " + p;
            case Circle c -> "circle";
            case Square s -> "square";
            case null -> "null";
            default -> "other";
        };
    }

    static String block() {
        var s = """
            hello
              world""";
        return s;
    }

    static int check(Object o) {
        if (o instanceof Point(int x, int y) && x > 0) {
            return x + y;
        }
        return helper(List.of(1));
    }

    static int helper(List<Integer> l) { return l.size(); }
}
