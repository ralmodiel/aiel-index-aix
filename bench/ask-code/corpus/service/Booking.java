package demo.service;

import java.util.List;

public class Booking {
    /** Two reservations of one room collide when their time ranges intersect. */
    public boolean collides(Slot a, Slot b) {
        if (!a.room.equals(b.room)) {
            return false;
        }
        return a.start < b.end && b.start < a.end;
    }

    /** Refuse a new reservation if any existing one collides with it. */
    public void checkFree(Slot wanted, List<Slot> existing) {
        for (Slot s : existing) {
            if (collides(wanted, s)) {
                throw new ConflictException("room already taken");
            }
        }
    }
}
