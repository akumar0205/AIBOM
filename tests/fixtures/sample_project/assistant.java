import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.model.input.PromptTemplate;

public class Assistant {
    public void run() {
        OpenAiChatModel model = OpenAiChatModel.builder().modelName("gpt-4o-mini").build();
        ToolSpecification tool = ToolSpecification.builder().name("weather_lookup").build();
        PromptTemplate promptTemplate = PromptTemplate.from("Summarize {{topic}} for an auditor");
    }
}
