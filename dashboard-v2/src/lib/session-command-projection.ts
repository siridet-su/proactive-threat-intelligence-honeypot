import { analystCommandText } from "@/lib/session-intelligence";

type JsonRecord = Record<string, unknown>;

const COMMAND_EVENT_IDS = new Set([
  "cowrie.command.failed",
  "cowrie.command.input",
  "cowrie.command.success",
]);

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function eventIdentifier(value: JsonRecord): string {
  return typeof value.event_id === "string" ? value.event_id : "";
}

/**
 * Join the private, exact-session command projection to the public event
 * metadata without ever copying the full Cowrie event or structured auth fields.
 */
export function projectAdminCommandRecords(expectedSessionId: string, detailValue: unknown, commandValue: unknown): JsonRecord[] {
  const detailCandidate = isRecord(detailValue) ? detailValue : {};
  const commandProjection = isRecord(commandValue) ? commandValue : {};
  if (
    !expectedSessionId
    || commandProjection.session_id !== expectedSessionId
    || (typeof detailCandidate.session_id === "string" && detailCandidate.session_id !== expectedSessionId)
  ) return [];
  const detail = detailCandidate;
  const publicEvents = list(detail.events || detail.events_table_rows)
    .filter(isRecord)
    .filter((event) => event.command_event === true);
  const classifications = list(detail.classification_events).filter(isRecord);

  return list(commandProjection.commands)
    .filter(isRecord)
    .filter((command) => COMMAND_EVENT_IDS.has(String(command.eventid || "").toLowerCase()))
    .map((command, index) => {
      const eventId = eventIdentifier(command);
      const publicEvent = publicEvents.find((event) => eventIdentifier(event) === eventId);
      const classification = classifications.find((item) => {
        const durableOrder = isRecord(item.durable_evidence_order) ? item.durable_evidence_order : {};
        return durableOrder.event_id === eventId;
      });
      const input = analystCommandText(command);
      return {
        sequence: index + 1,
        event_id: eventId,
        eventid: command.eventid,
        timestamp: command.timestamp || publicEvent?.timestamp || publicEvent?.received_at || null,
        session_id: commandProjection.session_id || detail.session_id || null,
        command_event: true,
        command_text_available: input !== null,
        ...(input !== null ? { input } : { command_text_unavailable_reason: "stored_input_redacted_or_empty" }),
        input_truncated: command.input_truncated === true,
        classification_event_id: classification?.evidence_id,
        classification_technique: classification?.ttp || null,
        sensitive: true,
      };
    });
}
