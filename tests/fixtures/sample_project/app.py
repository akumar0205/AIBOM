from langchain_openai import ChatOpenAI
from langchain.agents import initialize_agent
from langchain.vectorstores import FAISS
from langchain.prompts import PromptTemplate

llm = ChatOpenAI(model="gpt-4o-mini")
agent = initialize_agent([])
store = FAISS.from_texts([], None)
prompt = PromptTemplate(template="Hello {name}", input_variables=["name"])
