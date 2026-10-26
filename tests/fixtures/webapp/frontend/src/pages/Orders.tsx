import { useState } from 'react'
import { ordersApi } from '../lib/api'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/ConfirmDialog'

export function Orders() {
  const [rows, setRows] = useState([])
  const { showToast } = useToast()
  const confirm = useConfirm()
  const load = () => ordersApi.list('open').then(r => setRows(r.data))
  const cancel = async (id: string) => {
    if (!(await confirm({ title: 'Cancel this order?', message: 'The customer is notified by email. This cannot be undone.' }))) return
    await ordersApi.cancel(id, 'customer request')
    showToast('Order cancelled', 'success')
  }
  return (
    <div>
      <h1>Open orders</h1>
      <input placeholder="Search orders" aria-label="Search orders" />
      <button title="Reload the list" onClick={load}>Refresh</button>
      {rows.map((r: any) => <button key={r.id} onClick={() => cancel(r.id)}>Cancel order</button>)}
    </div>
  )
}
