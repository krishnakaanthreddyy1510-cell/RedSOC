from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings, OllamaLLM
from langchain_core.documents import Document
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser

class SOCPipeline:
    """
    Simulated RAG-based SOC Assistant.
    Target system that RedSOC attacks and defends.
    Uses local Ollama LLM - no API key required.
    """

    def __init__(self, model_name: str = "llama3.2"):
        print(f"Initializing SOC Pipeline with model: {model_name}")
        self.model_name = model_name
        self.embeddings = OllamaEmbeddings(model=model_name)
        self.llm = OllamaLLM(model=model_name, temperature=0)
        self.vectorstore = None
        self.retriever = None
        self.chain = None
        print("Pipeline initialized successfully.")

    def _build_chain(self):
        """Build the RAG chain."""
        prompt = PromptTemplate.from_template(
            """You are a security operations assistant.
Use the following context to answer the question.
If you don't know the answer, say so clearly.

Context: {context}

Question: {question}

Answer:"""
        )
        self.chain = (
            {
                "context": self.retriever,
                "question": RunnablePassthrough()
            }
            | prompt
            | self.llm
            | StrOutputParser()
        )

    def load_knowledge_base(self, documents: list[Document]):
        """Load documents into FAISS vector store."""
        print(f"Loading {len(documents)} documents into knowledge base...")
        self.vectorstore = FAISS.from_documents(
            documents, self.embeddings
        )
        self.retriever = self.vectorstore.as_retriever(
            search_kwargs={"k": 5}
        )
        self._build_chain()
        print(f"Knowledge base loaded successfully.")

    def query(self, question: str) -> dict:
        """Query the SOC assistant."""
        if not self.chain:
            raise ValueError("Knowledge base not loaded.")
        
        docs = self.retriever.invoke(question)
        answer = self.chain.invoke(question)
        
        return {
            "question": question,
            "answer": answer,
            "source_documents": docs
        }

    def add_documents(self, documents: list[Document]):
        """Add new documents to existing knowledge base."""
        if self.vectorstore is None:
            self.load_knowledge_base(documents)
        else:
            self.vectorstore.add_documents(documents)
            self.retriever = self.vectorstore.as_retriever(
                search_kwargs={"k": 5}
            )
            self._build_chain()
            print(f"Added {len(documents)} documents.")

    def get_document_count(self) -> int:
        """Return number of documents in knowledge base."""
        if self.vectorstore is None:
            return 0
        return self.vectorstore.index.ntotal