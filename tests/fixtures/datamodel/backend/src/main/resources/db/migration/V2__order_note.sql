ALTER TABLE orders ADD COLUMN IF NOT EXISTS note text;
CREATE UNIQUE INDEX idx_orders_cust ON orders (customer_name, status);
ALTER TABLE orders ADD CONSTRAINT orders_qty_uq UNIQUE (id, quantity);
