import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Read-only, cached view of the files being scanned. Rules get file contents only through
 * this, so each file is read from disk once however many rules look at it.
 */
export class ProjectFiles {
  private text = new Map<string, string | null>();
  private lineStarts = new Map<string, number[]>();

  constructor(
    readonly root: string,
    readonly files: readonly string[],
  ) {}

  /** File contents, or null if the file is binary or unreadable. */
  read(file: string): string | null {
    if (this.text.has(file)) return this.text.get(file)!;
    let content: string | null = null;
    try {
      const buf = readFileSync(join(this.root, file));
      content = looksBinary(buf) ? null : buf.toString("utf8");
    } catch {
      content = null;
    }
    this.text.set(file, content);
    return content;
  }

  json(file: string): unknown {
    const t = this.read(file);
    if (t === null) return null;
    try {
      return JSON.parse(t);
    } catch {
      return null;
    }
  }

  lines(file: string): string[] {
    return (this.read(file) ?? "").split(/\r?\n/);
  }

  /** Converts a character offset to a 1-based line and column. */
  position(file: string, offset: number): { line: number; column: number } {
    let starts = this.lineStarts.get(file);
    if (!starts) {
      starts = [0];
      const t = this.read(file) ?? "";
      for (let i = 0; i < t.length; i++) if (t.charCodeAt(i) === 10) starts.push(i + 1);
      this.lineStarts.set(file, starts);
    }
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - starts[lo]! + 1 };
  }
}

function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}
