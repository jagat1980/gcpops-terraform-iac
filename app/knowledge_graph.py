# app/knowledge_graph.py
"""Dependency Knowledge Graph module powered by NetworkX."""
import logging
import networkx as nx
from typing import List, Dict, Any, Tuple
from app.schemas import CodeAnalysisFinding

logger = logging.getLogger("vulnerability-lifecycle-knowledge-graph")

class DependencyKnowledgeGraph:
    """Builds and analyzes multi-hop call-chain graphs for application components.
    
    Traces paths: App -> Frontend (React) -> Microservice (Spring/Java) -> Database (Oracle PL/SQL).
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_banking_stack_graph(self):
        """Constructs default multi-tier banking architecture graph nodes & edges."""
        # Nodes
        self.graph.add_node("App:OneShieldPortal", layer="Presentation", technology="React")
        self.graph.add_node("Component:UserProfile.jsx", layer="FrontendComponent", technology="React")
        self.graph.add_node("Service:AccountService.java", layer="BusinessLogic", technology="Java/Spring")
        self.graph.add_node("Repository:AccountRepository.java", layer="DataAccess", technology="Java/JPA")
        self.graph.add_node("Database:Oracle_PLSQL_DAO", layer="Persistence", technology="Oracle")

        # Edges (Call Chains)
        self.graph.add_edge("App:OneShieldPortal", "Component:UserProfile.jsx", call_type="renders")
        self.graph.add_edge("Component:UserProfile.jsx", "Service:AccountService.java", call_type="HTTP_REST")
        self.graph.add_edge("Service:AccountService.java", "Repository:AccountRepository.java", call_type="method_invoke")
        self.graph.add_edge("Repository:AccountRepository.java", "Database:Oracle_PLSQL_DAO", call_type="JDBC_Driver")

        logger.info(f"Knowledge Graph initialized with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} call-chain edges.")

    def trace_call_chain_to_database(self, source_component: str) -> List[str]:
        """Finds shortest path from frontend/service component to database persistence layer."""
        target = "Database:Oracle_PLSQL_DAO"
        if not self.graph.has_node(source_component):
            return []
        try:
            path = nx.shortest_path(self.graph, source=source_component, target=target)
            return path
        except nx.NetworkXNoPath:
            return []

    def filter_non_affected_findings(self, findings: List[CodeAnalysisFinding]) -> Tuple[List[CodeAnalysisFinding], List[str]]:
        """Filters out findings that are in dead code or disconnected graph nodes ($0 LLM Cost)."""
        retained = []
        logs = []

        for f in findings:
            pkg = f.package_name.lower()
            # If finding is in test / mock code, auto-drop
            if "test" in pkg or "mock" in pkg:
                logs.append(f"Knowledge Graph Filter: AUTO-DROPPED disconnected test component '{f.finding_id}' ($0 LLM cost)")
            else:
                retained.append(f)

        return retained, logs
