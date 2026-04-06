from langchain_core.documents import Document
from src.pipeline import SOCPipeline

def test_basic_pipeline():
    # Sample security documents for knowledge base
    documents = [
        Document(
            page_content="Ransomware is malware that encrypts files and demands payment. Response: isolate the affected system immediately, notify security team, do not pay ransom.",
            metadata={"source": "incident_response_playbook", "type": "clean"}
        ),
        Document(
            page_content="SQL injection attacks occur when malicious SQL code is inserted into input fields. Prevention: use parameterized queries and input validation.",
            metadata={"source": "vulnerability_guide", "type": "clean"}
        ),
        Document(
            page_content="Phishing emails impersonate trusted entities to steal credentials. Detection: check sender domain, hover over links before clicking, verify requests via phone.",
            metadata={"source": "threat_intel", "type": "clean"}
        ),
        Document(
            page_content="DDoS attacks overwhelm servers with traffic. Mitigation: rate limiting, traffic scrubbing, CDN protection, contact ISP for upstream filtering.",
            metadata={"source": "incident_response_playbook", "type": "clean"}
        ),
        Document(
            page_content="Lateral movement occurs when attackers move through a network after initial compromise. Detection: monitor unusual internal traffic, privileged account usage.",
            metadata={"source": "threat_intel", "type": "clean"}
        ),
    ]

    print("\n--- Initializing SOC Pipeline ---")
    pipeline = SOCPipeline(model_name="llama3.2")

    print("\n--- Loading Knowledge Base ---")
    pipeline.load_knowledge_base(documents)
    print(f"Documents in knowledge base: {pipeline.get_document_count()}")

    print("\n--- Testing Query ---")
    question = "What should I do if ransomware is detected on a system?"
    result = pipeline.query(question)

    print(f"\nQuestion: {result['question']}")
    print(f"\nAnswer: {result['answer']}")
    print(f"\nSources used: {len(result['source_documents'])} documents")

    print("\n--- Pipeline test complete ---")

if __name__ == "__main__":
    test_basic_pipeline()