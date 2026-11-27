// Flow tracer training on the Learn page: complete exercises, and every screen label it names still exists.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { TRAINING, TRAINING_BEFORE, TRAINING_CHECK, TRAINING_INTRO } from "../src/data/flowTraining";

const walk = (d: string): string[] => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));
// The app's own text, without the training file itself.
const app = walk("src").filter((f) => /\.(tsx?|css)$/.test(f) && !f.endsWith("flowTraining.ts")).map((f) => readFileSync(f, "utf8")).join("\n");
const routes = [...readFileSync("src/App.tsx", "utf8").matchAll(/\{ id: "([a-z]+)", label:/g)].map((m) => m[1]);
const labels = (t: string) => [...t.matchAll(/\*\*([^*]+)\*\*/g)].map((m) => m[1]);

describe("Flow tracer training", () => {
  it("every exercise has a goal, steps, a success check and a lesson", () => {
    expect(TRAINING.length).toBeGreaterThanOrEqual(6);
    expect(new Set(TRAINING.map((t) => t.id)).size).toBe(TRAINING.length);
    for (const t of TRAINING) {
      expect(t.goal.length, t.id).toBeGreaterThan(20);
      expect(t.steps.length, t.id).toBeGreaterThanOrEqual(3);
      expect(t.success.length, t.id).toBeGreaterThan(20);
      expect(t.learned.length, t.id).toBeGreaterThan(20);
      expect(routes, t.id).toContain(t.open.route);
    }
  });

  it("names only buttons and headings that exist in the app", () => {
    const all = [TRAINING_INTRO, ...TRAINING_BEFORE, ...TRAINING.flatMap((t) => [...t.steps, t.success, t.learned, t.needs ?? ""])].flatMap(labels);
    expect(all.length).toBeGreaterThan(15);
    const missing = [...new Set(all)].filter((l) => !app.includes(l));
    expect(missing).toEqual([]);
  });

  it("check questions point at real exercises", () => {
    for (const c of TRAINING_CHECK) expect(TRAINING.map((t) => t.id)).toContain(c.exercise);
  });

  it("is on the Learn page and linked from Flow tracer", () => {
    expect(readFileSync("src/views/Learn.tsx", "utf8")).toContain("<FlowTraining />");
    expect(readFileSync("src/views/FlowTracer.tsx", "utf8")).toContain('section: "flow-training"');
  });

  it("has no job or career content", () => {
    const text = JSON.stringify([TRAINING, TRAINING_CHECK, TRAINING_INTRO]);
    expect(text).not.toMatch(/interview|resume|job skill|career|hiring manager/i);
  });
});
