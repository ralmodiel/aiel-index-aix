package com.acme.service;

import com.acme.model.Order;
import com.acme.model.OrderRepository;
import jakarta.persistence.EntityManager;

public class OrderService {
    EntityManager em;
    OrderRepository customers;

    public void cancel(String id) {
        Order o = Order.findByStatus("open");
        o.status = "cancelled";
        o.persist();
        customers.findByFullName("x");
        audit(id);
    }

    public Object totals() {
        return em.createNativeQuery("SELECT o.status, count(*) FROM orders o JOIN order_lines l ON l.order_id = o.id GROUP BY o.status").getResultList();
    }

    void audit(String id) {
        em.createNativeQuery("INSERT INTO audit_log (id, what) VALUES (?, 'cancel')").executeUpdate();
    }
}
