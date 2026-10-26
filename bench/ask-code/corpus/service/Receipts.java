package demo.service;

public class Receipts {
    /** Reject a receipt number that was already used for another payment. */
    public void requireUniqueNumber(String number) {
        long used = Payment.count("receiptNo", number);
        if (used > 0) {
            throw new ConflictException("receipt number " + number + " already exists");
        }
    }

    /** Next receipt number in the running sequence, zero padded. */
    public String nextNumber(long last) {
        return String.format("%08d", last + 1);
    }
}
