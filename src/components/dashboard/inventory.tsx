"use client";

/**
 * VulnCheck Local — System Inventory section: host profile, disks,
 * network interfaces and detected software packages.
 */

import { HardDrive, Info, MonitorCog, Network, Package } from "lucide-react";
import { useDashboardStore } from "@/lib/client/store";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";
import { DefItem, SectionCard } from "./section-card";
import { EmptyState } from "./empty-state";
import { formatDiskSize, formatMemoryGiB, formatUptime } from "./utils";

export function InventorySection() {
  const detail = useDashboardStore((s) => s.detail);
  const profile = detail?.profile ?? null;
  const { t } = useI18n();

  if (!profile) {
    return (
      <EmptyState
        icon={MonitorCog}
        title={t("inventory.emptyTitle")}
        description={t("inventory.emptyDescription")}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Host info */}
      <SectionCard title={t("inventory.host")} description={profile.osName} icon={MonitorCog}>
        <dl className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <DefItem label={t("inventory.hostname")} value={profile.hostname} mono />
          <DefItem label={t("inventory.osName")} value={profile.osName} />
          <DefItem label={t("inventory.osVersion")} value={profile.osVersion} />
          <DefItem label={t("inventory.osBuild")} value={profile.osBuild} mono />
          <DefItem label={t("inventory.kernel")} value={profile.kernelVersion ?? "—"} mono />
          <DefItem label={t("inventory.architecture")} value={profile.arch} mono />
          <DefItem label={t("inventory.cpuModel")} value={profile.cpuModel ?? "—"} />
          <DefItem label={t("inventory.cpuCores")} value={profile.cpuCores ?? "—"} />
          <DefItem label={t("inventory.totalRam")} value={formatMemoryGiB(profile.totalMemoryMb)} />
          <DefItem label={t("inventory.usedRam")} value={formatMemoryGiB(profile.usedMemoryMb)} />
          <DefItem label={t("inventory.uptime")} value={formatUptime(profile.uptimeHours)} />
          <DefItem label={t("inventory.primaryIp")} value={profile.primaryIp ?? "—"} mono />
        </dl>
      </SectionCard>

      {/* Disks */}
      <SectionCard title={t("inventory.disks")} description={t("inventory.disksDescription")} icon={HardDrive}>
        {profile.disks.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("inventory.disksEmpty")}</p>
        ) : (
          <div className="overflow-x-auto vc-scroll">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("inventory.device")}</TableHead>
                  <TableHead>{t("inventory.type")}</TableHead>
                  <TableHead>{t("inventory.size")}</TableHead>
                  <TableHead>{t("inventory.used")}</TableHead>
                  <TableHead>{t("inventory.mount")}</TableHead>
                  <TableHead className="w-40">{t("inventory.usage")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {profile.disks.map((disk) => (
                  <TableRow key={`${disk.device}-${disk.mount}`}>
                    <TableCell className="font-mono text-xs">{disk.device}</TableCell>
                    <TableCell className="text-muted-foreground">{disk.fstype || "—"}</TableCell>
                    <TableCell className="tabular-nums">{formatDiskSize(disk.sizeMb)}</TableCell>
                    <TableCell className="tabular-nums">{formatDiskSize(disk.usedMb)}</TableCell>
                    <TableCell className="font-mono text-xs">{disk.mount}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
                          <div
                            className={cn(
                              "h-full rounded-full",
                              disk.usePercent > 90 ? "bg-red-500" : "bg-primary"
                            )}
                            style={{ width: `${Math.min(100, Math.max(0, disk.usePercent))}%` }}
                          />
                        </div>
                        <span
                          className={cn(
                            "text-xs tabular-nums",
                            disk.usePercent > 90 ? "text-red-500" : "text-muted-foreground"
                          )}
                        >
                          {Math.round(disk.usePercent)}%
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      {/* Interfaces */}
      <SectionCard title={t("inventory.interfaces")} description={t("inventory.interfacesDescription")} icon={Network}>
        {profile.interfaces.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("inventory.interfacesEmpty")}</p>
        ) : (
          <div className="overflow-x-auto vc-scroll">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("inventory.name")}</TableHead>
                  <TableHead>{t("inventory.ipv4")}</TableHead>
                  <TableHead>{t("inventory.ipv6")}</TableHead>
                  <TableHead>{t("inventory.mac")}</TableHead>
                  <TableHead>{t("inventory.scope")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {profile.interfaces.map((iface) => (
                  <TableRow key={iface.name}>
                    <TableCell className="font-mono text-xs">{iface.name}</TableCell>
                    <TableCell className="font-mono text-xs">{iface.ipv4 ?? "—"}</TableCell>
                    <TableCell className="max-w-48 truncate font-mono text-xs" title={iface.ipv6 ?? undefined}>
                      {iface.ipv6 ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{iface.mac ?? "—"}</TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          iface.internal
                            ? "border-primary/40 bg-primary/10 text-primary"
                            : "border-zinc-400/50 bg-zinc-400/10 text-zinc-400"
                        }
                      >
                        {iface.internal ? t("inventory.internal") : t("inventory.external")}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      {/* Software */}
      <SectionCard
        title={t("inventory.software")}
        description={
          profile.packageCount == null
            ? t("inventory.softwareNoCount")
            : t("inventory.softwareCount", { count: profile.packageCount })
        }
        icon={Package}
      >
        {profile.packages.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("inventory.softwareEmpty")}</p>
        ) : (
          <div className="max-h-96 overflow-y-auto rounded-md border bg-muted/30 p-3 vc-scroll">
            <ul className="space-y-0.5" aria-label={t("inventory.packagesAria")}>
              {profile.packages.map((pkg, i) => (
                <li key={`${pkg}-${i}`} className="font-mono text-xs text-muted-foreground">
                  {pkg}
                </li>
              ))}
            </ul>
          </div>
        )}
        <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
          <Info aria-hidden="true" className="size-3.5" />
          {t("inventory.capNote")}
        </p>
      </SectionCard>
    </div>
  );
}
