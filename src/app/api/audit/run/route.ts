import { NextResponse } from 'next/server';
import { AuditConflictError, startAuditRun } from '@/lib/vulncheck/auditors/engine';

export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST() {
  try {
    const sessionId = await startAuditRun();
    return NextResponse.json({ sessionId }, { status: 202 });
  } catch (err) {
    if (err instanceof AuditConflictError) {
      return NextResponse.json({ error: 'An audit is already running' }, { status: 409 });
    }
    console.error('[api:audit/run] error', err);
    return NextResponse.json({ error: 'Failed to start the audit session' }, { status: 500 });
  }
}
