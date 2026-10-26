package shop;

import jakarta.inject.Inject;

@ApplicationScoped
public class OrderService extends BaseService implements Auditable {
    @Inject
    PriceCalculator calc;
    private final OrderRepository repo;

    public OrderService(OrderRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public Order place(String customer, int qty) {
        Order o = new Order(customer);
        o.total = calc.total(qty);
        o.persist();
        audit("placed");
        return finish(o);
    }

    public Order place(String customer) {
        return place(customer, 1);
    }

    private Order finish(Order o) {
        repo.save(o);
        Order.find("customer", o.customer);
        return o;
    }

    static int helper() {
        return Util.clamp(3);
    }

    public static class Receipt {
        int amount;

        String render() {
            return "r" + helper();
        }
    }
}
