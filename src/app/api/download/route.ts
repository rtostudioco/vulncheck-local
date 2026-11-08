import { NextResponse } from 'next/server';
import { readFile, stat } from 'fs/promises';
import path from 'path';

export const dynamic = 'force-dynamic';

/**
 * VulnCheck Local — project artifact download.
 *
 * Serves whitelisted build artifacts from the local `download/` directory
 * (never arbitrary paths) as an HTTP attachment so the dashboard can offer
 * a one-click "Download project package" action.
 */

const ARTIFACTS_DIR = 'download';
const DEFAULT_ARTIFACT = 'vulncheck-local-v1.1.0-github.zip';

/** Exact file names that may be served (allowlist, no path traversal). */
const ALLOWED_ARTIFACTS: ReadonlySet<string> = new Set([DEFAULT_ARTIFACT]);

export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const requested = searchParams.get('file') ?? DEFAULT_ARTIFACT;

    if (!ALLOWED_ARTIFACTS.has(requested)) {
      return NextResponse.json({ error: 'Artifact not available' }, { status: 403 });
    }

    // path.basename() as defense-in-depth against traversal on top of the allowlist.
    const safeName = path.basename(requested);
    const filePath = path.join(process.cwd(), ARTIFACTS_DIR, safeName);

    const info = await stat(filePath).catch(() => null);
    if (!info || !info.isFile()) {
      return NextResponse.json({ error: 'Artifact not found on this machine' }, { status: 404 });
    }

    const bytes = await readFile(filePath);
    return new NextResponse(new Uint8Array(bytes), {
      status: 200,
      headers: {
        'Content-Type': 'application/zip',
        'Content-Length': String(info.size),
        'Content-Disposition': `attachment; filename="${safeName}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (err) {
    console.error('[api:download] error', err);
    return NextResponse.json({ error: 'Failed to serve the artifact' }, { status: 500 });
  }
}
