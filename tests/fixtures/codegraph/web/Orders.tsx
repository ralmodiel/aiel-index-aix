import { useState } from 'react';
import { ordersApi, formatMoney as fm } from './api';
import OrderRow from './OrderRow';

export default function Orders() {
  const [rows, setRows] = useState([]);
  const load = async () => {
    setRows(await ordersApi.list());
  };
  function cancel(id: string) {
    ordersApi.cancel(id);
    return fm(1);
  }
  return <OrderRow onCancel={cancel} onLoad={load} />;
}

class Store {
  constructor(private api: Client) {}
  refresh() {
    return this.api.fetchAll();
  }
}
