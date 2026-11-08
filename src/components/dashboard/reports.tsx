"use client";

/**
 * VulnCheck Local — Reports section: PDF/JSON/CSV export cards for the
 * selected completed session plus the generated-reports history table.
 */

import { useCallback, useEffect, useState } from "react";
import { format } from "date-fns";
import {
  AlertCircle,
  FileJson,
  FileSpreadsheet,
  FileText,
  Loader2,
  RefreshCw,
} from "lucide-react";
import type { ReportHistoryDTO } from "@/lib/vulncheck/core/types";
import { useDashboardStore } from "@/lib/client/store";
import { downloadExport, downloadPdfReport, fetchReportHistory } from "@/lib/client/api";
import { getT, useI18n } from "@/lib/i18n";
import { toast } from "@/hooks/use-toast";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { EmptyState } from "./empty-state";
import { SectionCard } from "./section-card";
import { scoreBandTextClass } from "./utils";

const FORMATS = [
  {
    key: "pdf" as const,
    icon: FileText,
    titleKey: "reports.format.pdf.title",
    descriptionKey: "reports.format.pdf.description",
  },
  {
    key: "json" as const,
    icon: FileJson,
    titleKey: "reports.format.json.title",
    descriptionKey: "reports.format.json.description",
  },
  {
    key: "csv" as const,
    icon: FileSpreadsheet,
    titleKey: "reports.format.csv.title",
    descriptionKey: "reports.format.csv.description",
  },
];

function formatBadgeClass(formatValue: string): string {
  switch (formatValue.toLowerCase()) {
    case "pdf":
      return "border-red-500/50 bg-red-500/10 text-red-500";
    case "json":
      return "border-amber-500/50 bg-amber-500/10 text-amber-500";
    case "csv":
      return "border-emerald-500/50 bg-emerald-500/10 text-emerald-500";
    default:
      return "text-muted-foreground";
  }
}

export function ReportsSection() {
  const { t } = useI18n();
  const detail = useDashboardStore((s) => s.detail);
  const [reports, setReports] = useState<ReportHistoryDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const canDownload = detail != null && detail.status === "COMPLETED";

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { reports: list } = await fetchReportHistory();
      setReports(list);
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : getT()("reports.error.fallback"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const handleDownload = (formatKey: "pdf" | "json" | "csv") => {
    if (!canDownload || !detail) return;
    try {
      if (formatKey === "pdf") {
        downloadPdfReport(detail.id);
      } else {
        downloadExport(detail.id, formatKey);
      }
      toast({
        title: t("reports.toast.started.title"),
        description: t("reports.toast.started.description"),
      });
      // Give the backend a moment to record the generated report, then refresh.
      window.setTimeout(() => void loadHistory(), 1200);
    } catch {
      toast({
        title: t("reports.toast.failed.title"),
        description: t("reports.toast.failed.description"),
        variant: "destructive",
      });
    }
  };

  return (
    <div className="space-y-6">
      <SectionCard
        title={t("reports.title")}
        description={
          canDownload
            ? t("reports.subtitle.ready")
            : t("reports.subtitle.select")
        }
        icon={FileText}
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {FORMATS.map((fmt) => {
            const Icon = fmt.icon;
            return (
              <div key={fmt.key} className="flex flex-col rounded-lg border bg-card p-4">
                <div className="flex items-center gap-2">
                  <div className="flex size-9 items-center justify-center rounded-md bg-primary/10 text-primary">
                    <Icon aria-hidden="true" className="size-4" />
                  </div>
                  <h3 className="text-sm font-semibold">{t(fmt.titleKey)}</h3>
                </div>
                <p className="mt-2 flex-1 text-xs leading-relaxed text-muted-foreground text-pretty">
                  {t(fmt.descriptionKey)}
                </p>
                <Button
                  className="mt-4 h-11 w-full"
                  disabled={!canDownload}
                  onClick={() => handleDownload(fmt.key)}
                >
                  <Icon aria-hidden="true" className="size-4" />
                  {t("reports.action.download", { format: fmt.key.toUpperCase() })}
                </Button>
              </div>
            );
          })}
        </div>
        {!canDownload ? (
          <p className="mt-4 text-xs text-muted-foreground">
            {t("reports.note.disabled")}
          </p>
        ) : null}
      </SectionCard>

      <SectionCard
        title={t("reports.history.title")}
        description={t("reports.history.subtitle")}
        icon={FileJson}
        actions={
          <Button
            variant="outline"
            size="sm"
            className="h-9"
            onClick={() => void loadHistory()}
            disabled={loading}
            aria-label={t("reports.aria.refresh")}
          >
            {loading ? (
              <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
            ) : (
              <RefreshCw aria-hidden="true" className="size-3.5" />
            )}
            {t("reports.action.refresh")}
          </Button>
        }
        contentClassName="space-y-4"
      >
        {error ? (
          <Alert variant="destructive">
            <AlertCircle aria-hidden="true" />
            <AlertTitle>{t("reports.error.title")}</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        {loading && reports.length === 0 ? (
          <div className="space-y-2">
            <div className="h-9 animate-pulse rounded-md bg-muted" />
            <div className="h-9 animate-pulse rounded-md bg-muted" />
            <div className="h-9 animate-pulse rounded-md bg-muted" />
          </div>
        ) : !error && reports.length === 0 ? (
          <EmptyState
            icon={FileText}
            title={t("reports.empty.title")}
            description={t("reports.empty.description")}
          />
        ) : (
          <div className="max-h-80 overflow-y-auto rounded-md border vc-scroll">
            <Table>
              <TableHeader className="sticky top-0 bg-card/95">
                <TableRow>
                  <TableHead>{t("reports.col.generated")}</TableHead>
                  <TableHead>{t("reports.col.format")}</TableHead>
                  <TableHead>{t("reports.col.file")}</TableHead>
                  <TableHead>{t("reports.col.sessionDate")}</TableHead>
                  <TableHead>{t("reports.col.score")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell className="whitespace-nowrap tabular-nums">
                      {format(new Date(report.generatedAt), "MMM d, yyyy HH:mm")}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn("uppercase", formatBadgeClass(report.format))}>
                        {report.format}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-56 truncate font-mono text-xs" title={report.fileName}>
                      {report.fileName}
                    </TableCell>
                    <TableCell className="whitespace-nowrap tabular-nums text-muted-foreground">
                      {format(new Date(report.sessionDate), "MMM d, yyyy HH:mm")}
                    </TableCell>
                    <TableCell className={cn("font-medium tabular-nums", scoreBandTextClass(report.overallScore))}>
                      {report.overallScore ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
