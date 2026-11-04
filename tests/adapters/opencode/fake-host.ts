import type { Plugin } from "@opencode/plugin";
import type { ToolContext } from "@opencode/plugin/promise/tool";

// A minimal in-memory OpenCode V2 plugin host for tests: it records tool, skill, and agent
// registrations and runs `permission.assert` through the registered `evaluate` hooks.

export type FakeTool = {
  readonly name: string;
  readonly description: string;
  readonly input: unknown;
  readonly execute: (input: unknown, context: ToolContext) => Promise<{ readonly content?: unknown; readonly metadata?: Record<string, unknown> }>;
};

export type FakeAssert = {
  readonly action: string;
  readonly resources: readonly string[];
  readonly metadata?: Record<string, unknown>;
  readonly effect: string;
  readonly message?: string;
};

type Evaluation = { action: string; resources: readonly string[]; metadata?: Record<string, unknown>; effect: string; message?: string; sessionID: string };

export type FakeCommand = {
  readonly name: string;
  readonly description?: string;
  readonly execute: (input: { sessionID: string; prompt: Record<string, unknown>; delivery: string }) => Promise<void>;
};

export type FakeHost = {
  readonly ctx: Plugin.Context;
  readonly tools: Map<string, FakeTool>;
  readonly commands: Map<string, FakeCommand>;
  /** Prompts plugins sent through `session.prompt`. */
  readonly prompts: Record<string, unknown>[];
  readonly skills: Map<string, Record<string, unknown>>;
  readonly agents: Map<string, Record<string, unknown>>;
  readonly asserts: FakeAssert[];
  /** Decides an `ask`; resolve to allow, throw to reject. Defaults to allow. */
  decide: (evaluation: FakeAssert) => Promise<void>;
  /** The effect configured rules produce before hooks run. Defaults to OpenCode's `allow`. */
  configuredEffect: "allow" | "ask" | "deny";
  readonly disposed: string[];
};

export function toolContext(signal: AbortSignal = new AbortController().signal): ToolContext {
  return { sessionID: "ses_test", agent: "build", messageID: "msg_test", id: "call_test", signal, progress: async () => undefined } as unknown as ToolContext;
}

export function fakeHost(directory: string, options: Record<string, unknown> = {}, seed: { skills?: Record<string, Record<string, unknown>>; agents?: Record<string, Record<string, unknown>> } = {}): FakeHost {
  const hooks: ((evaluation: Evaluation) => void | Promise<void>)[] = [];
  const host: FakeHost = {
    ctx: undefined as unknown as Plugin.Context,
    tools: new Map(),
    commands: new Map(),
    prompts: [],
    skills: new Map(Object.entries(seed.skills ?? {})),
    agents: new Map(Object.entries(seed.agents ?? {})),
    asserts: [],
    decide: async () => undefined,
    configuredEffect: "allow",
    disposed: [],
  };
  const registration = (name: string, undo: () => void) => ({
    dispose: async () => {
      undo();
      host.disposed.push(name);
    },
  });
  const ctx = {
    location: { directory, project: { id: "project_test", directory, canonical: directory } },
    options,
    tool: {
      transform: async (callback: (editor: { add: (tool: FakeTool) => void }) => void) => {
        const added: string[] = [];
        callback({ add: (tool) => { host.tools.set(tool.name, tool); added.push(tool.name); } });
        return registration("tool", () => { for (const name of added) host.tools.delete(name); });
      },
    },
    command: {
      transform: async (callback: (editor: { add: (command: FakeCommand) => void }) => void) => {
        const added: string[] = [];
        callback({ add: (command) => { host.commands.set(command.name, command); added.push(command.name); } });
        return registration("command", () => { for (const name of added) host.commands.delete(name); });
      },
    },
    session: {
      prompt: async (input: Record<string, unknown>) => {
        host.prompts.push(input);
        return { id: "msg_prompted" };
      },
    },
    permission: {
      hook: async (_name: "evaluate", callback: (evaluation: Evaluation) => void | Promise<void>) => {
        hooks.push(callback);
        return registration("permission", () => hooks.splice(hooks.indexOf(callback), 1));
      },
      assert: async (input: { sessionID: string; action: string; resources: readonly string[]; metadata?: Record<string, unknown> }) => {
        const evaluation: Evaluation = { ...input, effect: host.configuredEffect };
        if (evaluation.effect !== "deny") for (const hook of hooks) await hook(evaluation);
        const record: FakeAssert = { action: evaluation.action, resources: evaluation.resources, ...(evaluation.metadata ? { metadata: evaluation.metadata } : {}), effect: evaluation.effect, ...(evaluation.message ? { message: evaluation.message } : {}) };
        host.asserts.push(record);
        if (evaluation.effect === "deny") throw new Error(evaluation.message ?? `Permission denied: ${evaluation.action}`);
        if (evaluation.effect === "ask") await host.decide(record);
      },
    },
    skill: {
      transform: async (callback: (editor: { get: (id: string) => unknown; add: (skill: Record<string, unknown>) => void }) => void) => {
        const added: string[] = [];
        callback({ get: (id) => host.skills.get(id), add: (skill) => { host.skills.set(String(skill.id), skill); added.push(String(skill.id)); } });
        return registration("skill", () => { for (const id of added) host.skills.delete(id); });
      },
    },
    agent: {
      transform: async (callback: (editor: { get: (id: string) => unknown; update: (id: string, update: (draft: Record<string, unknown>) => void) => void }) => void) => {
        callback({
          get: (id) => host.agents.get(id),
          update: (id, update) => {
            const draft = structuredClone(host.agents.get(id) ?? { id, request: { headers: {} }, permissions: [] });
            update(draft);
            host.agents.set(id, draft);
          },
        });
        return registration("agent", () => undefined);
      },
    },
  };
  (host as { ctx: Plugin.Context }).ctx = ctx as unknown as Plugin.Context;
  return host;
}
