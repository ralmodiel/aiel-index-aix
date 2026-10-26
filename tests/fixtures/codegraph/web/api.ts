import { http } from './http';

export const ordersApi = {
  list: () => http.get('/api/orders'),
  cancel: async (id: string) => http.post(`/api/orders/${id}/cancel`),
};

export function formatMoney(n: number) {
  return n.toFixed(2);
}
