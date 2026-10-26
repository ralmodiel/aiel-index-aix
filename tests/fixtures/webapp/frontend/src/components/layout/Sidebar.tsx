const STAFF_ROLES = ['clerk', 'admin', 'manager']
export const navigationGroups = [
  {
    title: 'Sales',
    roles: STAFF_ROLES,
    items: [
      { name: 'Orders', href: '/orders', keywords: 'sales cancel refund', tooltip: 'Find and cancel orders' },
      { name: 'Reports', href: '/reports', roles: ['manager'], tabs: [{ title: 'Monthly', key: 'monthly' }] },
    ],
  },
]
export function Sidebar() {
  return <nav aria-label="Main menu">{navigationGroups.length}</nav>
}
