import OpenAI from "openai";

const DEFAULT_MODEL = process.env.APP_MODEL || "gpt-4o-mini";

export function createClient(modelName: string = DEFAULT_MODEL) {
  return new OpenAI({ model: modelName });
}

export const client = createClient();

const PINNED_MODEL = "gpt-4o-mini";
export const pinned = new OpenAI({ model: PINNED_MODEL });
