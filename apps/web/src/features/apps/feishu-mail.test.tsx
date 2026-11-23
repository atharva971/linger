import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createTestTeamHubRuntime } from "@/test/teamhub-test-runtime";
import { TeamHubError } from "@/features/teamhub/teamhub-error";
import { TeamHubRuntimeProvider } from "@/features/teamhub/teamhub-runtime";
import type {
  TeamHubExternalApp,
  TeamHubExternalAppList,
} from "@/features/teamhub/teamhub-types";

import { ConnectedAppsPage } from "./connected-apps-page";
import { FeishuOAuthCompletePage } from "./feishu-oauth-complete-page";

describe("Feishu Mail", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("is not offered on the Apps page; Agents ask for it in chat", async () => {
    const runtime = createTestTeamHubRuntime();
    const base = await runtime.client.listExternalApps();
    vi.spyOn(runtime.client, "listExternalApps").mockResolvedValue(
      catalog(base),
    );
    vi.spyOn(runtime.client, "listExternalConnections").mockResolvedValue({
      connections: [],
    });
    renderPage(runtime);

    expect(
      await screen.findByRole("button", { name: "Connect Gmail" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Connect Feishu Mail" }),
    ).toBeNull();
    expect(screen.queryByText("App ID")).toBeNull();
  });

  it("stays reachable once connected, so it can be disconnected", async () => {
    const runtime = createTestTeamHubRuntime();
    const base = await runtime.client.listExternalApps();
    vi.spyOn(runtime.client, "listExternalApps").mockResolvedValue(
      catalog(base),
    );
    const existing = (await runtime.client.listExternalConnections())
      .connections[0]!;
    vi.spyOn(runtime.client, "listExternalConnections").mockResolvedValue({
      connections: [
        {
          ...existing,
          id: "connection_feishu",
          provider: "feishu_mail",
          status: "active",
          identity_label: "owner@example.test",
        },
      ],
    });
    renderPage(runtime);

    fireEvent.click(
      await screen.findByRole("button", { name: "Connected only" }),
    );
    const connected = screen.getByRole("region", {
      name: "Application connections",
    });
    await waitFor(() =>
      expect(
        within(connected)
          .getAllByRole("article")
          .map((card) => within(card).getAllByRole("button")[0]!.ariaLabel),
      ).toEqual(["Feishu Mail"]),
    );
  });
});

describe("Feishu consent return page", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState(null, "", "/");
  });

  function renderReturn(outcome: Promise<void> = Promise.resolve()) {
    const runtime = createTestTeamHubRuntime();
    const complete = vi
      .spyOn(runtime.client, "completeFeishuAuthorization")
      .mockReturnValue(outcome);
    render(
      <TeamHubRuntimeProvider runtime={runtime}>
        <FeishuOAuthCompletePage />
      </TeamHubRuntimeProvider>,
    );
    return complete;
  }

  it("hands the code and state to TeamHub, then closes", async () => {
    window.history.replaceState(
      null,
      "",
      "/oauth/feishu-complete?code=code-1&state=signed-state",
    );
    const close = vi.spyOn(window, "close").mockImplementation(() => undefined);

    const complete = renderReturn();

    expect(complete).toHaveBeenCalledWith("signed-state", "code-1");
    expect(
      await screen.findByRole("heading", { name: "Authorization complete" }),
    ).toBeVisible();
    await waitFor(() => expect(close).toHaveBeenCalled(), { timeout: 3000 });
  });

  it("hands a code to TeamHub once when the page mounts again", async () => {
    window.history.replaceState(
      null,
      "",
      "/oauth/feishu-complete?code=code-3&state=signed-state",
    );
    vi.spyOn(window, "close").mockImplementation(() => undefined);
    const runtime = createTestTeamHubRuntime();
    const complete = vi
      .spyOn(runtime.client, "completeFeishuAuthorization")
      .mockResolvedValue();
    const page = (
      <TeamHubRuntimeProvider runtime={runtime}>
        <FeishuOAuthCompletePage />
      </TeamHubRuntimeProvider>
    );

    render(<StrictMode>{page}</StrictMode>);

    expect(
      await screen.findByRole("heading", { name: "Authorization complete" }),
    ).toBeVisible();
    expect(complete).toHaveBeenCalledTimes(1);
  });

  it("reports a cancelled consent without calling TeamHub", async () => {
    window.history.replaceState(
      null,
      "",
      "/oauth/feishu-complete?error=access_denied&state=signed-state",
    );

    const complete = renderReturn();

    expect(
      await screen.findByText(
        "Authorization was cancelled. Close this window and connect again.",
      ),
    ).toBeVisible();
    expect(complete).not.toHaveBeenCalled();
  });

  it("lists the permissions the Feishu app still lacks", async () => {
    window.history.replaceState(
      null,
      "",
      "/oauth/feishu-complete?code=code-2&state=signed-state",
    );

    renderReturn(
      Promise.reject(
        new TeamHubError({
          code: "FEISHU_SCOPES_MISSING",
          details: [
            {
              code: "missing",
              field: "scope",
              reason: "mail:user_mailbox.message:send",
            },
          ],
          message: "The Feishu app does not grant every mail permission yet",
          status: 400,
        }),
      ),
    );

    expect(
      await screen.findByText("mail:user_mailbox.message:send"),
    ).toBeVisible();
    expect(screen.getByText(/Ask your admin to enable them/)).toBeVisible();
  });
});

function catalog(base: TeamHubExternalAppList): TeamHubExternalAppList {
  const feishuMail: TeamHubExternalApp = {
    key: "feishu_mail",
    display_name: "Feishu Mail",
    description:
      "Let Agents read and send your Feishu or Lark mail; new mail syncs to your Wiki each night.",
    availability: "available",
    capabilities: ["connect", "agent_tools"],
    allows_multiple_connections: true,
    supports_reauthorization: true,
  };
  return {
    ...base,
    apps: [...base.apps.filter((app) => app.key !== "feishu_mail"), feishuMail],
  };
}

function renderPage(runtime: ReturnType<typeof createTestTeamHubRuntime>) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <MemoryRouter initialEntries={["/apps"]}>
      <QueryClientProvider client={queryClient}>
        <TeamHubRuntimeProvider runtime={runtime}>
          <ConnectedAppsPage />
        </TeamHubRuntimeProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}
