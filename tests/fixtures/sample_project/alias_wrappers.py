from langchain_openai import ChatOpenAI as ChatModel
from langchain.agents import initialize_agent as init_agent

PrimaryModel = ChatModel


def model_factory(model_name: str):
    return PrimaryModel(model=model_name)


def wrapped_model():
    constructor = PrimaryModel
    return constructor(model_name="gpt-4.1-mini")


llm = model_factory("gpt-4o-mini")
agent = init_agent([])
