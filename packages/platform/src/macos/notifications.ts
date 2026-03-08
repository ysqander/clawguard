import type { NotificationClient, NotificationReceipt, NotificationRequest } from "../types.js";
import type { CommandRunner } from "../shared/command-runner.js";

export class MacosNotificationClient implements NotificationClient {
  constructor(private readonly commandRunner: CommandRunner) {}

  async send(request: NotificationRequest): Promise<NotificationReceipt> {
    const script = buildDisplayNotificationScript(request);
    await this.commandRunner.run("osascript", ["-e", script], {
      rejectOnNonZero: true
    });

    return {
      deliveredAt: new Date().toISOString()
    };
  }
}

export function buildDisplayNotificationScript(
  request: NotificationRequest
): string {
  const body = toAppleScriptString(normalizeNotificationValue(request.body));
  const title = toAppleScriptString(normalizeNotificationValue(request.title));
  const subtitleClause =
    request.subtitle !== undefined
      ? ` subtitle ${toAppleScriptString(normalizeNotificationValue(request.subtitle))}`
      : "";

  return `display notification ${body} with title ${title}${subtitleClause}`;
}

function normalizeNotificationValue(value: string): string {
  return value.replace(/\s+/gu, " ").trim();
}

function toAppleScriptString(value: string): string {
  return `"${value.replace(/\\/gu, "\\\\").replace(/"/gu, '\\"')}"`;
}
