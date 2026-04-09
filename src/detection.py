from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings
import numpy as np

class DetectionLayer:
    """
    RedSOC Detection Layer.
    Three detection mechanisms for identifying adversarial attacks.
    
    Novel contribution: unified detection pipeline for SOC context.
    """

    def __init__(self, model_name: str = "llama3.2", threshold: float = 0.7):
        self.embeddings = OllamaEmbeddings(model=model_name)
        self.threshold = threshold
        self.detection_results = []

    # ─── DETECTOR 1: SEMANTIC ANOMALY ─────────────────────────────────────
    def semantic_anomaly_score(self, query: str, documents: list[Document]) -> dict:
        """
        Detects poisoned documents by measuring semantic similarity
        between the query and retrieved documents.
        Low similarity = potential poisoning.
        """
        query_embedding = self.embeddings.embed_query(query)
        
        scores = []
        for doc in documents:
            doc_embedding = self.embeddings.embed_query(doc.page_content)
            similarity = np.dot(query_embedding, doc_embedding) / (
                np.linalg.norm(query_embedding) * np.linalg.norm(doc_embedding)
            )
            scores.append({
                "content_preview": doc.page_content[:100],
                "source": doc.metadata.get("source", "unknown"),
                "type": doc.metadata.get("type", "unknown"),
                "similarity_score": round(float(similarity), 4)
            })

        avg_score = np.mean([s["similarity_score"] for s in scores])
        min_score = np.min([s["similarity_score"] for s in scores])
        anomaly_detected = bool(min_score < self.threshold)

        result = {
            "detector": "semantic_anomaly",
            "query": query,
            "average_similarity": round(float(avg_score), 4),
            "minimum_similarity": round(float(min_score), 4),
            "threshold": self.threshold,
            "anomaly_detected": anomaly_detected,
            "document_scores": scores
        }

        self.detection_results.append(result)
        return result

    # ─── DETECTOR 2: PROVENANCE TRACKER ───────────────────────────────────
    def provenance_check(self, documents: list[Document]) -> dict:
        """
        Tracks document sources and flags unknown or suspicious origins.
        Known sources are whitelisted. Unknown sources are flagged.
        """
        trusted_sources = {
            "incident_response_playbook",
            "vulnerability_guide",
            "threat_intel",
            "mitre_attack",
            "nvd_cve",
            "internal_wiki"
        }

        flagged = []
        clean = []

        for doc in documents:
            source = doc.metadata.get("source", "unknown")
            doc_type = doc.metadata.get("type", "unknown")

            if source not in trusted_sources or doc_type == "poisoned":
                flagged.append({
                    "source": source,
                    "type": doc_type,
                    "content_preview": doc.page_content[:100]
                })
            else:
                clean.append(source)

        anomaly_detected = len(flagged) > 0

        result = {
            "detector": "provenance_check",
            "total_documents": len(documents),
            "clean_documents": len(clean),
            "flagged_documents": len(flagged),
            "flagged_sources": flagged,
            "anomaly_detected": anomaly_detected
        }

        self.detection_results.append(result)
        return result

    # ─── DETECTOR 3: CONSISTENCY CHECKER ──────────────────────────────────
    def response_consistency_check(self, query: str, answer: str, documents: list[Document]) -> dict:
        """
        Checks whether the answer is consistent with retrieved documents.
        Large divergence between answer and source content = potential injection.
        """
        answer_embedding = self.embeddings.embed_query(answer)

        consistency_scores = []
        for doc in documents:
            doc_embedding = self.embeddings.embed_query(doc.page_content)
            consistency = np.dot(answer_embedding, doc_embedding) / (
                np.linalg.norm(answer_embedding) * np.linalg.norm(doc_embedding)
            )
            consistency_scores.append(float(consistency))

        avg_consistency = np.mean(consistency_scores)
        anomaly_detected = bool(avg_consistency < self.threshold)

        result = {
            "detector": "response_consistency",
            "query": query,
            "answer_preview": answer[:150],
            "average_consistency": round(avg_consistency, 4),
            "threshold": self.threshold,
            "anomaly_detected": anomaly_detected
        }

        self.detection_results.append(result)
        return result

    # ─── UNIFIED DETECTION ────────────────────────────────────────────────
    def run_all_detectors(self, query: str, answer: str, documents: list[Document]) -> dict:
        """
        Runs all three detectors and returns unified verdict.
        """
        semantic = self.semantic_anomaly_score(query, documents)
        provenance = self.provenance_check(documents)
        consistency = self.response_consistency_check(query, answer, documents)

        detectors_triggered = sum([
            semantic["anomaly_detected"],
            provenance["anomaly_detected"],
            consistency["anomaly_detected"]
        ])

        threat_level = "HIGH" if detectors_triggered >= 2 else \
                      "MEDIUM" if detectors_triggered == 1 else "LOW"

        return {
            "query": query,
            "threat_level": threat_level,
            "detectors_triggered": detectors_triggered,
            "semantic_anomaly": semantic,
            "provenance_check": provenance,
            "response_consistency": consistency,
            "recommendation": "BLOCK and ALERT analyst" if threat_level == "HIGH"
                             else "FLAG for review" if threat_level == "MEDIUM"
                             else "PASS - no anomaly detected"
        }

    def get_detection_summary(self) -> dict:
        """Returns detection performance summary."""
        if not self.detection_results:
            return {}

        true_positives = sum(1 for r in self.detection_results if r["anomaly_detected"])
        total = len(self.detection_results)

        return {
            "total_detections_run": total,
            "anomalies_flagged": true_positives,
            "clean_passed": total - true_positives,
            "flag_rate": round(true_positives / total * 100, 2) if total > 0 else 0
        }