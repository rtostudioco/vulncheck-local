"use client";

/**
 * VulnCheck Local — Audit History section: local session table with
 * load/delete actions and the retention note.
 */

import { format } from "date-fns";
import { Database, History, Loader2, Play, Trash2 } from "lucide-react";
import { useDashboardStore } from "@/lib/client/store";
import { useI18n } from "@/lib/i18n";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
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
import type { SessionSummary } from "@/lib/vulncheck/core/types";
import { EmptyState } from "./empty-state";
import { SectionCard } from "./section-card";
import { AuditStatusBadge } from "./status-badge";
import { gradeBadgeClasses, scoreBandTextClass } from "./utils";

function SessionRow({ session }: { session: SessionSummary }) {
  const { t } = useI18n();
  const selectSession = useDashboardStore((s) => s.selectSession);
  const removeSession = useDashboardStore((s) => s.removeSession);
  const loadingDetail = useDashboardStore((s) => s.loadingDetail);

  return (
    <TableRow>
      <TableCell className="whitespace-nowrap tabular-nums">
        {format(new Date(session.startedAt), "MMM d, yyyy HH:mm")}
      </TableCell>
      <TableCell className="text-muted-foreground">{session.platform}</TableCell>
      <TableCell className={cn("font-medium tabular-nums", scoreBandTextClass(session.overallScore))}>
        {session.overallScore ?? "—"}
      </TableCell>
      <TableCell>
        <Badge variant="outline" className={gradeBadgeClasses(session.grade)}>
          {session.grade ?? "—"}
        </Badge>
      </TableCell>
      <TableCell className="tabular-nums">{session.findingsCount}</TableCell>
      <TableCell className="tabular-nums text-muted-foreground">
        {session.coverage == null ? "—" : `${Math.round(session.coverage)}%`}
      </TableCell>
      <TableCell>
        <AuditStatusBadge status={session.status} />
      </TableCell>
      <TableCell>
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="outline"
            size="sm"
            className="h-9"
            disabled={loadingDetail}
            onClick={() => {
              void selectSession(session.id);
              useDashboardStore.getState().setSection("overview");
            }}
          >
            {loadingDetail ? (
              <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
            ) : (
              <Play aria-hidden="true" className="size-3.5" />
            )}
            {t("history.action.load")}
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="size-9 text-muted-foreground hover:text-destructive"
                aria-label={t("history.aria.deleteSession", {
                  date: format(new Date(session.startedAt), "MMM d, yyyy HH:mm"),
                })}
              >
                <Trash2 aria-hidden="true" className="size-4" />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{t("history.delete.title")}</AlertDialogTitle>
                <AlertDialogDescription>{t("history.delete.description")}</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("history.delete.cancel")}</AlertDialogCancel>
                <AlertDialogAction
                  className="bg-destructive text-white hover:bg-destructive/90"
                  onClick={() => void removeSession(session.id)}
                >
                  {t("history.delete.confirm")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </TableCell>
    </TableRow>
  );
}

export function HistorySection() {
  const { t } = useI18n();
  const sessions = useDashboardStore((s) => s.sessions);
  const sessionsLoading = useDashboardStore((s) => s.sessionsLoading);
  const retentionDays = useDashboardStore((s) => s.meta?.retentionDays ?? null);

  return (
    <div className="space-y-6">
      <SectionCard
        title={t("history.title")}
        description={t("history.subtitle")}
        icon={History}
        contentClassName="space-y-4"
      >
        {sessions.length === 0 && !sessionsLoading ? (
          <EmptyState
            icon={History}
            title={t("history.empty.title")}
            description={t("history.empty.description")}
          />
        ) : (
          <div className="max-h-105 overflow-y-auto rounded-md border vc-scroll">
            <Table>
              <TableHeader className="bg-card/95 sticky top-0">
                <TableRow>
                  <TableHead>{t("history.col.date")}</TableHead>
                  <TableHead>{t("history.col.platform")}</TableHead>
                  <TableHead>{t("history.col.score")}</TableHead>
                  <TableHead>{t("history.col.grade")}</TableHead>
                  <TableHead>{t("history.col.findings")}</TableHead>
                  <TableHead>{t("history.col.coverage")}</TableHead>
                  <TableHead>{t("history.col.status")}</TableHead>
                  <TableHead className="text-right">{t("history.col.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => (
                  <SessionRow key={session.id} session={session} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Database aria-hidden="true" className="size-3.5" />
          {t("history.retention", { days: retentionDays ?? "—" })}
        </p>
      </SectionCard>
    </div>
  );
}
