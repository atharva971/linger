import { useEffect, useState } from "react";

import type { TeamHubClient } from "@/features/teamhub/teamhub-client";
import { TeamHubError } from "@/features/teamhub/teamhub-error";
import { useTeamHubRuntime } from "@/features/teamhub/teamhub-runtime";
import { useT } from "@/i18n/use-translation";

import { connectorMessages as m } from "./connectors.messages";

// A popup the app opened closes itself this long after a success.
const CLOSE_AFTER_MS = 1500;

// Feishu accepts a code once, and development mounts this page twice, so each
// code is handed to TeamHub once and every mount waits on that one request.
const completions = new Map<string, Promise<void>>();

function completeOnce(client: TeamHubClient, state: string, code: string) {
  let completion = completions.get(code);
  if (!completion) {
    completion = client.completeFeishuAuthorization(state, code);
    completions.set(code, completion);
  }
  return completion;
}

type Outcome =
  | { kind: "pending" }
  | { kind: "done" }
  | { kind: "cancelled" }
  | { kind: "scopes"; scopes: string[] }
  | { kind: "failed"; message: string };

/**
 * The page Feishu returns consent to. It hands the code to TeamHub, which
 * needs no session for it, so this also works in a browser that is not signed
 * in to Linger, such as the one the desktop app opens.
 */
export function FeishuOAuthCompletePage() {
  const { client } = useTeamHubRuntime();
  const t = useT();
  const [outcome, setOutcome] = useState<Outcome>({ kind: "pending" });

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const code = query.get("code");
    const state = query.get("state");
    if (query.get("error") || !code || !state) {
      setOutcome({ kind: "cancelled" });
      return;
    }
    let active = true;
    completeOnce(client, state, code).then(
      () => {
        if (active) setOutcome({ kind: "done" });
      },
      (error: unknown) => {
        if (active) setOutcome(failure(error, t));
      },
    );
    return () => {
      active = false;
    };
  }, [client, t]);

  useEffect(() => {
    if (outcome.kind !== "done") return;
    const timer = setTimeout(() => window.close(), CLOSE_AFTER_MS);
    return () => clearTimeout(timer);
  }, [outcome.kind]);

  return (
    <main className="flex min-h-dvh items-center justify-center bg-background px-6 text-center text-foreground">
      <div className="max-w-md" role="status">
        {outcome.kind === "pending" ? (
          <p className="text-sm text-muted-foreground">
            {t(m.feishuFinishing)}
          </p>
        ) : outcome.kind === "done" ? (
          <>
            <h1 className="text-lg">{t(m.authorizationComplete)}</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              {t(m.canCloseWindow)}
            </p>
          </>
        ) : outcome.kind === "scopes" ? (
          <>
            <p className="text-sm">{t(m.feishuScopesMissing)}</p>
            <ul className="mt-3 space-y-1 font-mono text-xs text-muted-foreground">
              {outcome.scopes.map((scope) => (
                <li key={scope}>{scope}</li>
              ))}
            </ul>
          </>
        ) : (
          <p className="text-sm">
            {outcome.kind === "cancelled"
              ? t(m.feishuAuthorizationCancelled)
              : outcome.message}
          </p>
        )}
      </div>
    </main>
  );
}

function failure(error: unknown, t: ReturnType<typeof useT>): Outcome {
  if (!(error instanceof TeamHubError)) {
    return { kind: "failed", message: t(m.feishuAuthorizationFailed) };
  }
  switch (error.code) {
    case "FEISHU_SCOPES_MISSING":
      return {
        kind: "scopes",
        scopes: (error.details ?? []).map((detail) => detail.reason),
      };
    case "FEISHU_REFRESH_DISABLED":
      return { kind: "failed", message: t(m.feishuRefreshDisabled) };
    case "FEISHU_AUTHORIZATION_STALE":
    case "FEISHU_AUTHORIZATION_NOT_FOUND":
      return { kind: "failed", message: t(m.feishuAuthorizationStale) };
    default:
      return { kind: "failed", message: t(m.feishuAuthorizationFailed) };
  }
}
