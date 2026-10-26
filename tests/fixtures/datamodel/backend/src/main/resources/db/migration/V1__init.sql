-- baseline
CREATE TABLE customer (
    id varchar(26) PRIMARY KEY,
    full_name text NOT NULL
);

CREATE TABLE orders (
    id varchar(26) NOT NULL,
    customer_name varchar(80) NOT NULL,
    quantity integer,
    status varchar(20) DEFAULT 'open',
    owner_id varchar(26) REFERENCES customer(id),
    CONSTRAINT orders_pkey PRIMARY KEY (id)
);

CREATE TABLE order_lines (
    id varchar(26) PRIMARY KEY,
    order_id varchar(26) NOT NULL
);

ALTER TABLE ONLY order_lines
    ADD CONSTRAINT order_lines_order_fk FOREIGN KEY (order_id) REFERENCES orders(id);

CREATE TABLE audit_log (id varchar(26), what text);
