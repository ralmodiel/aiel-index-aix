import axios from 'axios'
export const api = axios.create({ baseURL: '/api' })

export const ordersApi = {
  list: (status?: string) => api.get('/orders', { params: { status } }),
  cancel: (id: string, reason: string) => api.post(`/orders/${id}/cancel`, { reason }),
  remove: (id: string) => api.delete(`/orders/${id}`),
}
