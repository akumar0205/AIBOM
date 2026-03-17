using OpenAI;
using Microsoft.SemanticKernel;

public class Assistant {
    public void Run() {
        var client = new OpenAIClient("sk-local");
        var tool = KernelFunctionFactory.CreateFromMethod(() => "ok", "weather_tool");
        var prompt = new PromptTemplateConfig("Write a haiku about {{topic}}");
    }
}
