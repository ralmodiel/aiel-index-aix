// Turn a stored timestamp into the label shown on a card.
export function relativeLabel(ts: number, now: number): string {
  const minutes = Math.floor((now - ts) / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return minutes + ' min ago';
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? hours + ' h ago' : Math.floor(hours / 24) + ' d ago';
}
