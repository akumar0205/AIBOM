import { ChatOpenAI as OpenAIChat } from "@langchain/openai";
import { tool as makeTool } from "@langchain/core/tools";
import { ChatPromptTemplate as Prompt } from "@langchain/core/prompts";

const LocalModel = OpenAIChat;
export const mkModel = (modelName: string) => new LocalModel({ model: modelName });
export const mkTool = () => makeTool(async () => "ok", { name: "factory_tool" });
export const mkPrompt = () => Prompt.fromTemplate("Edge template {input}");
