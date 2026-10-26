package shop;

@Entity
@Table(name = "orders")
public class Order extends PanacheEntity {
    public String customer;
    public int total;

    public Order(String customer) {
        this.customer = customer;
    }
}
