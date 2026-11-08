/**
 * MODULE L — report generation history persistence.
 */

import { db } from '@/lib/db';

export async function recordReport(sessionId: string, format: string, fileName: string): Promise<void> {
  await db.reportHistory.create({ data: { sessionId, format, fileName } });
}
