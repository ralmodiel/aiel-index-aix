# QA Findings — Round 1 (2026-09-01)

## P1

### 1. [bug/backend] Order cancel claims an email but OrderResource.cancel sends none

- [ ] `backend/src/main/java/com/acme/api/OrderResource.java:19` — **P1**

The confirm dialog says the customer is notified by email; the endpoint never sends one.

## P3

- [x] Search box in Orders ignores the status filter (fixed in abc1234)
