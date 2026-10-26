package com.acme.model;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface OrderRepository extends JpaRepository<Customer, String> {
    Customer findByFullName(String name);

    @Query("select c from Customer c where c.fullName like :p")
    java.util.List<Customer> search(String p);
}
