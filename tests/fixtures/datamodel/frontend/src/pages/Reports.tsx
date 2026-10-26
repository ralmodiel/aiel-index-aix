export default function Reports() {
  const data = fetch('/api/reports/monthly')
  return <PageHeader title="Reports" subtitle="Monthly sales by store" data={data} />
}
