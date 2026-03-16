import OpenAI from "openai";
import { ChatPromptTemplate } from "@langchain/core/prompts";
import { tool } from "@langchain/core/tools";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, model: "gpt-4o-mini" });
const summarize = tool(async () => "ok", { name: "summarize" });
const prompt = ChatPromptTemplate.fromTemplate("Summarize this text: {input}");

export { client, summarize, prompt };
