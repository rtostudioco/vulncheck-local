"use client";

/**
 * VulnCheck Local — Network Exposure section: listening ports sorted by
 * risk, interface recap cards and the passive-detection notice.
 */

import { Globe, Info, Network } from "lucide-react";
import { useDashboardStore } from "@/lib/client/store";
import { useI18n } from "@/lib/i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { PortInfo } from "@/lib/vulncheck/core/types";
import { EmptyState } from "./empty-state";
import { SectionCard } from "./section-card";
import { SeverityBadge } from "./severity-badge";
import { SEVERITY_RANK } from "./utils";

function BindScopeBadge({ scope }: { scope: PortInfo["bindScope"] }) {
  const { t } = useI18n();
  const classes =
    scope === "ALL"
      ? "border-red-500/50 bg-red-500/10 text-red-500"
      : scope === "LOCAL"
        ? "border-border bg-secondary text-secondary-foreground"
        : "border-zinc-400/50 bg-zinc-400/10 text-zinc-400";
  return (
    <Badge variant="outline" className={classes}>
      {t(`network.bindScope.${scope}`)}
    </Badge>
  );
}

function sortPorts(ports: PortInfo[]): PortInfo[] {
  return [...ports].sort(
    (a, b) =>
      SEVERITY_RANK[a.risk] - SEVERITY_RANK[b.risk] ||
      a.port - b.port ||
      a.proto.localeCompare(b.proto)
  );
}

export function NetworkExposureSection() {
  const { t } = useI18n();
  const detail = useDashboardStore((s) => s.detail);
  const network = detail?.network ?? null;

  if (!network) {
    return (
      <EmptyState
        icon={Network}
        title={t("network.empty.title")}
        description={t("network.empty.description")}
      />
    );
  }

  const ports = sortPorts(network.listeningPorts);
  const allBindCount = ports.filter((p) => p.bindScope === "ALL").length;
  // The session DTO does not retain the per-connection sample, so the
  // established-connections card reports what is available only.
  const established = null;

  const statCards = [
    { label: t("network.stat.listeningPorts"), value: ports.length },
    { label: t("network.stat.interfaces"), value: network.interfaces.length },
    { label: t("network.stat.boundAll"), value: allBindCount },
    {
      label: t("network.stat.established"),
      value: established == null ? "—" : established,
      hint: t("network.stat.establishedHint"),
    },
  ];

  return (
    <div className="space-y-6">
      <SectionCard
        title={t("network.ports.title")}
        description={t("network.ports.description")}
        icon={Network}
        contentClassName="space-y-4"
      >
        {ports.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("network.ports.empty")}</p>
        ) : (
          <div className="overflow-x-auto vc-scroll">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("network.table.proto")}</TableHead>
                  <TableHead>{t("network.table.port")}</TableHead>
                  <TableHead>{t("network.table.address")}</TableHead>
                  <TableHead>{t("network.table.bindScope")}</TableHead>
                  <TableHead>{t("network.table.service")}</TableHead>
                  <TableHead>{t("network.table.risk")}</TableHead>
                  <TableHead>{t("network.table.note")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ports.map((port) => (
                  <TableRow key={`${port.proto}-${port.port}-${port.address}`}>
                    <TableCell className="font-mono text-xs uppercase">{port.proto}</TableCell>
                    <TableCell className="font-mono text-xs tabular-nums">{port.port}</TableCell>
                    <TableCell className="font-mono text-xs">{port.address}</TableCell>
                    <TableCell>
                      <BindScopeBadge scope={port.bindScope} />
                    </TableCell>
                    <TableCell className="whitespace-nowrap">{port.service}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={port.risk} />
                    </TableCell>
                    <TableCell className="max-w-72 min-w-40 text-xs text-muted-foreground">
                      {port.note}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      <SectionCard
        title={t("network.summary.title")}
        description={t("network.summary.description")}
        icon={Globe}
      >
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {statCards.map((card) => (
            <div key={card.label} className="rounded-lg border bg-card p-4">
              <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                {card.label}
              </p>
              <p className="mt-1 text-2xl font-semibold tabular-nums">{card.value}</p>
              {card.hint ? <p className="mt-1 text-xs text-muted-foreground">{card.hint}</p> : null}
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard
        title={t("network.interfaces.title")}
        description={t("network.interfaces.description")}
        icon={Network}
      >
        {network.interfaces.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("network.interfaces.empty")}</p>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {network.interfaces.map((iface) => (
              <div key={iface.name} className="rounded-lg border bg-card p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm font-medium">{iface.name}</span>
                  <Badge
                    variant="outline"
                    className={
                      iface.internal
                        ? "border-primary/40 bg-primary/10 text-primary"
                        : "border-zinc-400/50 bg-zinc-400/10 text-zinc-400"
                    }
                  >
                    {iface.internal ? t("network.interfaces.internal") : t("network.interfaces.external")}
                  </Badge>
                </div>
                <p className="mt-2 truncate font-mono text-xs text-muted-foreground">
                  {t("network.interfaces.ipv4", { value: iface.ipv4 ?? "—" })}
                </p>
                <p className="truncate font-mono text-xs text-muted-foreground">
                  {t("network.interfaces.ipv6", { value: iface.ipv6 ?? "—" })}
                </p>
                <p className="truncate font-mono text-xs text-muted-foreground">
                  {t("network.interfaces.mac", { value: iface.mac ?? "—" })}
                </p>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      <Alert>
        <Info aria-hidden="true" />
        <AlertTitle>{t("network.passive.title")}</AlertTitle>
        <AlertDescription>{t("network.passive.description")}</AlertDescription>
      </Alert>
    </div>
  );
}
