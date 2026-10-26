package com.acme.model;

import jakarta.persistence.*;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import java.util.List;

@Entity
@Table(name = "orders")
public class Order extends PanacheEntityBase {
    @Id
    public String id;

    @Column(name = "customer_name", nullable = false, length = 80)
    public String customerName;

    public Integer quantity;

    public String status = "open";

    @ManyToOne
    @JoinColumn(name = "owner_id")
    public Customer owner;

    @OneToMany(mappedBy = "order")
    public List<OrderLine> lines;

    @Transient
    public String displayLabel;

    public static Order findByStatus(String status) {
        return find("status", status).firstResult();
    }
}
