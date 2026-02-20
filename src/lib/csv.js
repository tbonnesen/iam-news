function escapeCell(value) {
  const normalized = String(value ?? '');
  const escaped = normalized.replaceAll('"', '""');
  return `"${escaped}"`;
}

export function toCsv(rows) {
  const header = ['title', 'classification', 'severity', 'metric', 'description'];
  const body = rows.map((row) =>
    [
      escapeCell(row.title),
      escapeCell(row.classification),
      escapeCell(row.severity),
      escapeCell(row.metric),
      escapeCell(row.description),
    ].join(','),
  );
  return [header.join(','), ...body].join('\n');
}
