package demo.service;

public class Fees {
    /** Work out how much a customer owes after discounts and already paid amounts. */
    public double outstanding(Invoice inv) {
        double gross = inv.lines.stream().mapToDouble(l -> l.price * l.qty).sum();
        double discount = gross * inv.discountPct / 100.0;
        return gross - discount - inv.paid;
    }
}
