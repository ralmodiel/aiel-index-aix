package com.acme.model;

import jakarta.persistence.*;

@Entity
public class Customer {
    @Id
    public String id;
    public String fullName;
}
