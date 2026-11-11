import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap } from '@/lib/bootstrap'
import { serializeRule } from '@/lib/serialize'

export const dynamic = 'force-dynamic'

export async function GET() {
  try {
    await ensureBootstrap()
    const rules = await db.detectionRule.findMany({ orderBy: { id: 'asc' } })
    const counts = await db.alert.groupBy({ by: ['ruleId'], _count: { _all: true } })
    return NextResponse.json({
      rules: rules.map((r) => serializeRule(r, counts.find((c) => c.ruleId === r.id)?._count._all ?? 0)),
    })
  } catch (err) {
    console.error('rules list error', err)
    return NextResponse.json({ error: 'rules_failed' }, { status: 500 })
  }
}

export async function PATCH(req: NextRequest) {
  try {
    await ensureBootstrap()
    const body = (await req.json()) as { id?: string; enabled?: boolean }
    if (!body.id || typeof body.enabled !== 'boolean') {
      return NextResponse.json({ error: 'bad_request' }, { status: 400 })
    }
    const rule = await db.detectionRule.update({
      where: { id: body.id },
      data: { enabled: body.enabled },
    })
    await db.auditLog.create({
      data: { action: 'rule.toggle', target: body.id, detail: body.enabled ? 'enabled' : 'disabled' },
    })
    return NextResponse.json({ rule: serializeRule(rule) })
  } catch (err) {
    console.error('rules patch error', err)
    return NextResponse.json({ error: 'rule_update_failed' }, { status: 500 })
  }
}
