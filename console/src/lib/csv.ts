/** Reads a CSV a row at a time, inside the browser, so a large file never has to fit in memory or leave this machine. */
export async function* csvRows(file: Blob): AsyncGenerator<string[]> {
  const reader = file.stream().pipeThrough(new TextDecoderStream()).getReader();
  let row: string[] = [], cell = "", quoted = false, afterQuote = false, first = true, sawAny = false;
  const endCell = () => { row.push(cell); cell = ""; afterQuote = false; };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    let text = value;
    if (first) { text = text.replace(/^﻿/, ""); first = false; }
    for (let i = 0; i < text.length; i++) {
      const c = text[i]!;
      sawAny = true;
      if (quoted) {
        if (c !== '"') { cell += c; continue; }
        // A doubled quote is a literal quote; it may straddle two chunks, which the next branch handles.
        quoted = false; afterQuote = true;
        continue;
      }
      if (afterQuote && c === '"') { cell += '"'; quoted = true; afterQuote = false; continue; }
      if (c === '"' && cell === "") { quoted = true; continue; }
      if (c === ",") { endCell(); continue; }
      if (c === "\n") { endCell(); if (row.length > 1 || row[0] !== "") yield row; row = []; sawAny = false; continue; }
      if (c === "\r") continue;
      afterQuote = false;
      cell += c;
    }
  }
  if (sawAny || cell !== "" || row.length) { endCell(); if (row.length > 1 || row[0] !== "") yield row; }
}

export const csvLine = (cells: string[]) => cells.map((c) => (/[",\r\n]/.test(c) ? `"${c.replace(/"/g, '""')}"` : c)).join(",") + "\n";

export function saveFile(parts: BlobPart[], name: string, type = "text/csv") {
  const u = URL.createObjectURL(new Blob(parts, { type }));
  const a = document.createElement("a");
  a.href = u; a.download = name; a.click();
  URL.revokeObjectURL(u);
}
