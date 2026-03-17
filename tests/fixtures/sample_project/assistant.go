package main

import (
    "github.com/openai/openai-go"
    "github.com/tmc/langchaingo/prompts"
)

func main() {
    client := openai.NewClient()
    tool := tools.SearchTool
    tmpl := prompts.PromptTemplate("Translate {{text}} to French")
    _ = client
    _ = tool
    _ = tmpl
}
