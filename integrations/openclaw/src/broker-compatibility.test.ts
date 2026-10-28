import { afterEach, describe, expect, it, vi } from "vitest";
import entry from "./index.js";

type RegisteredTool = {
  name: string;
  execute: (callId: string, params: Record<string, unknown>) => Promise<{
    details: Record<string, unknown>;
  }>;
};

async function mailSend() {
  const registerTool = vi.fn<(tool: RegisteredTool) => void>();
  const api = {
    pluginConfig: {
      broker_url: "http://127.0.0.1:8765/",
      broker_token: "fixture-token",
      broker_timeout_seconds: 1,
    },
    registerTool,
  };
  await entry.register!(api as Parameters<NonNullable<typeof entry.register>>[0]);
  const tool = registerTool.mock.calls.find(([tool]) => tool.name === "mail_send")?.[0];
  expect(tool).toBeDefined();
  return tool!;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("registered SDK tool broker compatibility", () => {
  it("submits a proposal with bearer authentication without executing mail", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: "ALLOW", proposal_id: "fixture-proposal", requires_approval: true,
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const tool = await mailSend();
    const result = await tool.execute("fixture-call", {
      message_id: "fixture-message", recipients: ["recipient@example.invalid"],
      content: "fixture", actor_id: "fixture-actor",
    });

    expect(result.details).toMatchObject({
      status: "OK", broker_response: { proposal_id: "fixture-proposal", requires_approval: true },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, request] = fetch.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:8765/v1/proposals");
    expect(request).toMatchObject({ method: "POST", headers: { Authorization: "Bearer fixture-token" } });
    expect(JSON.parse(request.body)).toMatchObject({ action: "send", actor_id: "fixture-actor" });
  });

  it.each(["DENY", "LOCKDOWN"])("retains broker %s and pressure evidence", async (status) => {
    const pressure = { event_type: "vmga_pressure_signal", signal_type: "repeated_denial_escalation" };
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status, evidence_events: [pressure],
    })));
    vi.stubGlobal("fetch", fetch);
    const result = await (await mailSend()).execute("fixture-call", { content: "fixture" });
    expect(result.details).toMatchObject({ status: "DENY", broker_status: status, pressure_signals: [pressure] });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("denies non-success HTTP even when its body says ALLOW", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"status":"ALLOW"}', { status: 403 })));
    const result = await (await mailSend()).execute("fixture-call", {});
    expect(result.details).toMatchObject({ status: "DENY", http_status: 403 });
  });

  it("denies malformed JSON", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("invalid-json")));
    const result = await (await mailSend()).execute("fixture-call", {});
    expect(result.details).toMatchObject({ status: "DENY", error_code: "vmga_broker_bad_json" });
  });

  it("denies network failures without retrying", async () => {
    const fetch = vi.fn().mockRejectedValue(new Error("fixture-network-failure"));
    vi.stubGlobal("fetch", fetch);
    const result = await (await mailSend()).execute("fixture-call", {});
    expect(result.details).toMatchObject({ status: "DENY", error_code: "vmga_broker_unreachable" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("aborts and denies an unresponsive broker", async () => {
    vi.useFakeTimers();
    const fetch = vi.fn((_url: string, request: RequestInit) => new Promise((_resolve, reject) => {
      request.signal!.addEventListener("abort", () => reject(new Error("fixture-timeout")), { once: true });
    }));
    vi.stubGlobal("fetch", fetch);
    const tool = await mailSend();
    const pending = tool.execute("fixture-call", {});
    await vi.advanceTimersByTimeAsync(1000);
    expect((await pending).details).toMatchObject({ status: "DENY", error_code: "vmga_broker_unreachable" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
