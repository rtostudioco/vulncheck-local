/**
 * Flattened dictionaries — assembled from per-namespace files.
 * Keys become "<namespace>.<key>" (e.g. "overview.title", "common.status.FAIL").
 */

import commonEn from './en/common';
import settingsEn from './en/settings';
import overviewEn from './en/overview';
import inventoryEn from './en/inventory';
import assessmentEn from './en/assessment';
import findingsEn from './en/findings';
import networkEn from './en/network';
import complianceEn from './en/compliance';
import remediationEn from './en/remediation';
import historyEn from './en/history';
import reportsEn from './en/reports';

import commonEs from './es/common';
import settingsEs from './es/settings';
import overviewEs from './es/overview';
import inventoryEs from './es/inventory';
import assessmentEs from './es/assessment';
import findingsEs from './es/findings';
import networkEs from './es/network';
import complianceEs from './es/compliance';
import remediationEs from './es/remediation';
import historyEs from './es/history';
import reportsEs from './es/reports';

function flat(obj: Record<string, string>, prefix: string): Record<string, string> {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [`${prefix}.${k}`, v]));
}

/**
 * The `common` namespace also hosts grouped keys that components reference
 * WITHOUT the `common.` prefix (e.g. `t('nav.overview')`, `t('shell.runAudit')`).
 * For every `common.<k>` entry whose remainder contains a dot, also expose the
 * bare `<k>` form so both lookup styles resolve. Idempotent and additive.
 */
function withBareAliases(flatCommon: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = { ...flatCommon };
  for (const [k, v] of Object.entries(flatCommon)) {
    if (!k.startsWith('common.')) continue;
    const rest = k.slice('common.'.length);
    if (rest.includes('.') && !(rest in out)) out[rest] = v;
  }
  return out;
}

export const enDict: Record<string, string> = {
  ...withBareAliases(flat(commonEn, 'common')),
  ...flat(settingsEn, 'settings'),
  ...flat(overviewEn, 'overview'),
  ...flat(inventoryEn, 'inventory'),
  ...flat(assessmentEn, 'assessment'),
  ...flat(findingsEn, 'findings'),
  ...flat(networkEn, 'network'),
  ...flat(complianceEn, 'compliance'),
  ...flat(remediationEn, 'remediation'),
  ...flat(historyEn, 'history'),
  ...flat(reportsEn, 'reports'),
};

export const esDict: Record<string, string> = {
  ...withBareAliases(flat(commonEs, 'common')),
  ...flat(settingsEs, 'settings'),
  ...flat(overviewEs, 'overview'),
  ...flat(inventoryEs, 'inventory'),
  ...flat(assessmentEs, 'assessment'),
  ...flat(findingsEs, 'findings'),
  ...flat(networkEs, 'network'),
  ...flat(complianceEs, 'compliance'),
  ...flat(remediationEs, 'remediation'),
  ...flat(historyEs, 'history'),
  ...flat(reportsEs, 'reports'),
};
