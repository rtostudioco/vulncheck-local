/**
 * VulnCheck Local — dashboard client store (zustand).
 * Holds app meta, session list, active session detail, UI section state,
 * findings filters and the audit poller (setTimeout chain).
 */

import { create } from "zustand";

import { getT } from "@/lib/i18n";
import type {
  CheckStatus,
  MetaDTO,
  SessionDetail,
  SessionSummary,
  Severity,
} from "@/lib/vulncheck/core/types";
import {
  ApiError,
  deleteSession,
  fetchMeta,
  fetchSessionDetail,
  fetchSessions,
  saveSettings,
  startAudit,
} from "@/lib/client/api";
import { toast } from "@/hooks/use-toast";

export type SectionId =
  | "overview"
  | "inventory"
  | "assessment"
  | "findings"
  | "network"
  | "compliance"
  | "remediation"
  | "history"
  | "reports"
  | "settings";

export type SeverityFilter = Severity | "ALL";
export type StatusFilter = CheckStatus | "ALL";
export type CategoryFilter = string; // 'ALL' or a Category value

const POLL_INTERVAL_MS = 1500;

// Poller bookkeeping lives outside the store to avoid re-renders.
let pollTimer: ReturnType<typeof setTimeout> | null = null;
let pollTargetId: string | null = null;

function stopPolling(): void {
  if (pollTimer !== null) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  pollTargetId = null;
}

function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

interface DashboardState {
  // data
  meta: MetaDTO | null;
  sessions: SessionSummary[];
  activeId: string | null;
  detail: SessionDetail | null;

  // loading / errors
  loadingMeta: boolean;
  metaError: string | null;
  sessionsLoading: boolean;
  loadingDetail: boolean;
  detailError: string | null;
  runStarting: boolean;

  // ui state
  section: SectionId;
  findingsSeverity: SeverityFilter;
  findingsCategory: CategoryFilter;
  findingsStatus: StatusFilter;

  // actions
  init(): Promise<void>;
  loadLatest(): Promise<void>;
  refreshSessions(): Promise<void>;
  selectSession(id: string): Promise<void>;
  setSection(section: SectionId): void;
  setFindingsSeverity(value: SeverityFilter): void;
  setFindingsCategory(value: CategoryFilter): void;
  setFindingsStatus(value: StatusFilter): void;
  clearFindingsFilters(): void;
  openFindingsWithSeverity(severity: Severity): void;
  runAudit(): Promise<void>;
  removeSession(id: string): Promise<void>;
  removeAllSessions(): Promise<void>;
  updateSettings(patch: {
    aiConsentEnabled?: boolean;
    retentionDays?: number;
  }): Promise<void>;
}

function beginPolling(id: string): void {
  stopPolling();
  pollTargetId = id;

  const tick = async (): Promise<void> => {
    if (pollTargetId !== id) return;
    try {
      const detail = await fetchSessionDetail(id);
      const state = useDashboardStore.getState();
      if (pollTargetId !== id) return;

      // Update the visible detail only when the user is still on this session.
      if (state.activeId === id) {
        useDashboardStore.setState({ detail, detailError: null });
      }

      if (detail.status === "RUNNING") {
        pollTimer = setTimeout(() => {
          void tick();
        }, POLL_INTERVAL_MS);
        return;
      }

      // Terminal state reached.
      stopPolling();
      void useDashboardStore.getState().refreshSessions();
      if (detail.status === "COMPLETED") {
        const t = getT();
        toast({
          title: t("shell.toast.auditCompleted"),
          description: t("shell.toast.auditCompletedDesc", {
            score: detail.overallScore ?? "—",
            count: detail.findingsCount,
          }),
        });
      } else {
        const t = getT();
        toast({
          title: t("shell.toast.auditFailed"),
          description: t("shell.toast.auditFailedDesc"),
          variant: "destructive",
        });
      }
      if (useDashboardStore.getState().activeId === id) {
        useDashboardStore.setState({ section: "overview" });
      }
    } catch (err) {
      stopPolling();
      const t = getT();
      const message = errorMessage(err, t("shell.error.poll"));
      if (useDashboardStore.getState().activeId === id) {
        useDashboardStore.setState({ detailError: message });
      }
      toast({
        title: t("shell.toast.pollLost"),
        description: message,
        variant: "destructive",
      });
    }
  };

  pollTimer = setTimeout(() => {
    void tick();
  }, POLL_INTERVAL_MS);
}

export const useDashboardStore = create<DashboardState>()((set, get) => ({
  meta: null,
  sessions: [],
  activeId: null,
  detail: null,

  loadingMeta: false,
  metaError: null,
  sessionsLoading: false,
  loadingDetail: false,
  detailError: null,
  runStarting: false,

  section: "overview",
  findingsSeverity: "ALL",
  findingsCategory: "ALL",
  findingsStatus: "ALL",

  init: async () => {
    set({ loadingMeta: true, metaError: null });
    try {
      const meta = await fetchMeta();
      set({ meta });
    } catch (err) {
      const t = getT();
      set({
        metaError: errorMessage(err, t("shell.error.meta")),
      });
    } finally {
      set({ loadingMeta: false });
    }
    await get().loadLatest();
  },

  loadLatest: async () => {
    set({ sessionsLoading: true });
    try {
      const { sessions } = await fetchSessions();
      set({ sessions });
      const running = sessions.find((s) => s.status === "RUNNING");
      if (running) {
        await get().selectSession(running.id);
      } else if (sessions.length > 0) {
        await get().selectSession(sessions[0].id);
      } else {
        set({ activeId: null, detail: null, detailError: null });
      }
    } catch (err) {
      const t = getT();
      toast({
        title: t("shell.toast.loadSessionsFailed"),
        description: errorMessage(err, t("shell.error.sessionStore")),
        variant: "destructive",
      });
    } finally {
      set({ sessionsLoading: false });
    }
  },

  refreshSessions: async () => {
    try {
      const { sessions } = await fetchSessions();
      set({ sessions });
      // Resume polling if an audit is running and nothing is being polled.
      const running = sessions.find((s) => s.status === "RUNNING");
      if (running && pollTargetId === null) {
        beginPolling(running.id);
      }
    } catch (err) {
      const t = getT();
      toast({
        title: t("shell.toast.refreshFailed"),
        description: errorMessage(err, t("shell.error.sessionStore")),
        variant: "destructive",
      });
    }
  },

  selectSession: async (id: string) => {
    set({ activeId: id, loadingDetail: true, detailError: null });
    try {
      const detail = await fetchSessionDetail(id);
      set({ detail });
      if (detail.status === "RUNNING") {
        beginPolling(id);
      } else if (pollTargetId === id) {
        stopPolling();
      }
    } catch (err) {
      const t = getT();
      set({
        detail: null,
        detailError: errorMessage(err, t("shell.error.detail")),
      });
    } finally {
      set({ loadingDetail: false });
    }
  },

  setSection: (section: SectionId) => {
    set({ section });
  },

  setFindingsSeverity: (value: SeverityFilter) => set({ findingsSeverity: value }),
  setFindingsCategory: (value: CategoryFilter) => set({ findingsCategory: value }),
  setFindingsStatus: (value: StatusFilter) => set({ findingsStatus: value }),

  clearFindingsFilters: () => {
    set({ findingsSeverity: "ALL", findingsCategory: "ALL", findingsStatus: "ALL" });
  },

  openFindingsWithSeverity: (severity: Severity) => {
    set({ findingsSeverity: severity, section: "findings" });
  },

  runAudit: async () => {
    if (get().runStarting) return;
    if (get().sessions.some((s) => s.status === "RUNNING")) {
      const t = getT();
      toast({
        title: t("shell.toast.alreadyRunning"),
        description: t("shell.toast.alreadyRunningDesc"),
        variant: "destructive",
      });
      return;
    }
    set({ runStarting: true });
    try {
      const { sessionId } = await startAudit();
      set({
        activeId: sessionId,
        detail: null,
        detailError: null,
        section: "assessment",
      });
      const t = getT();
      toast({
        title: t("shell.toast.auditStarted"),
        description: t("shell.toast.auditStartedDesc"),
      });
      void get().refreshSessions();
      beginPolling(sessionId);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        const t = getT();
        toast({
          title: t("shell.toast.alreadyRunning"),
          description: err.message,
          variant: "destructive",
        });
      } else {
        const t = getT();
        toast({
          title: t("shell.toast.startFailed"),
          description: errorMessage(err, t("shell.error.startAudit")),
          variant: "destructive",
        });
      }
    } finally {
      set({ runStarting: false });
    }
  },

  removeSession: async (id: string) => {
    try {
      await deleteSession(id);
      if (get().activeId === id) {
        stopPolling();
        set({ activeId: null, detail: null, detailError: null });
      }
      const t = getT();
      toast({ title: t("shell.toast.sessionDeleted") });
      await get().refreshSessions();
      const { activeId, sessions } = get();
      if (!activeId && sessions.length > 0) {
        await get().selectSession(sessions[0].id);
      }
    } catch (err) {
      const t = getT();
      toast({
        title: t("shell.toast.deleteFailed"),
        description: errorMessage(err, t("shell.error.deleteSession")),
        variant: "destructive",
      });
    }
  },

  removeAllSessions: async () => {
    const ids = get().sessions.map((s) => s.id);
    let deleted = 0;
    let failed = 0;
    for (const id of ids) {
      try {
        await deleteSession(id);
        deleted += 1;
      } catch {
        failed += 1;
      }
    }
    stopPolling();
    set({ activeId: null, detail: null, detailError: null });
    await get().refreshSessions();
    const t = getT();
    toast({
      title:
        deleted === 1
          ? t("shell.toast.deletedOne", { count: deleted })
          : t("shell.toast.deletedMany", { count: deleted }),
      description:
        failed > 0
          ? failed === 1
            ? t("shell.toast.deleteFailedOne", { count: failed })
            : t("shell.toast.deleteFailedMany", { count: failed })
          : t("shell.toast.historyCleared"),
      variant: failed > 0 ? "destructive" : "default",
    });
  },

  updateSettings: async (patch) => {
    const settings = await saveSettings(patch);
    set((state) => ({
      meta: state.meta
        ? {
            ...state.meta,
            aiConsentEnabled: settings.aiConsentEnabled,
            retentionDays: settings.retentionDays,
          }
        : state.meta,
    }));
  },
}));
