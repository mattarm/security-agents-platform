#!/usr/bin/env python3
"""
Enterprise Topology Skill — technology stack mapping and dependency analysis.

Primary owner: Beta-4 (DevSecOps), Sigma (Metrics)
Wraps: enterprise-topology/src/core/graph/enterprise_graph.py

Capabilities:
  - Map enterprise technology topology (systems, services, dependencies)
  - Query dependency graphs for upstream / downstream impact
  - Calculate blast radius for changes or incidents
  - Identify critical paths through the service mesh
  - Generate topology reports with risk annotations
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, deque

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority, Severity,
)
from security_agents.skills.base_skill import BaseSecuritySkill

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

CRITICALITY_LEVELS = {"critical", "high", "medium", "low"}

SYSTEM_TYPES = {
    "service", "database", "queue", "cache", "storage", "cdn",
    "gateway", "load_balancer", "identity_provider", "monitoring",
}

DEPENDENCY_TYPES = {
    "runtime", "data", "auth", "event", "network", "config",
}

class EnterpriseTopologySkill(BaseSecuritySkill):
    """Enterprise technology topology mapping and dependency analysis."""

    SKILL_NAME = "enterprise_topology"
    DESCRIPTION = (
        "Technology stack mapping, dependency graph analysis, blast radius "
        "calculation, critical path identification, and topology reporting"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["beta_4_devsecops", "sigma_metrics"]
    REQUIRED_INTEGRATIONS = ["enterprise_topology"]

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------

    async def _setup(self):
        """Initialize the in-memory topology graph."""
        # Nodes: system_id -> metadata dict
        self.systems: Dict[str, Dict[str, Any]] = {}
        # Adjacency list: source_id -> [{target_id, dep_type, metadata}]
        self.edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # Reverse adjacency for upstream lookups
        self.reverse_edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    # ---------------------------------------------------------------------
    # Action dispatch
    # ---------------------------------------------------------------------

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate action.

        Supported actions:
          map_topology       -- register systems and dependencies
          get_dependencies   -- query upstream / downstream dependencies
          assess_blast_radius -- calculate change / incident blast radius
          find_critical_paths -- identify critical dependency paths
          generate_report    -- produce a topology summary report
        """
        action = parameters.get("action", "map_topology")
        dispatch = {
            "map_topology": self._map_topology,
            "get_dependencies": self._get_dependencies,
            "assess_blast_radius": self._assess_blast_radius,
            "find_critical_paths": self._find_critical_paths,
            "generate_report": self._generate_report,
        }
        handler = dispatch.get(action)
        if handler is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Unknown action '{action}'. "
                    f"Supported: {', '.join(dispatch.keys())}"
                ],
            )
        return await handler(parameters)

    # =====================================================================
    # map_topology
    # =====================================================================

    async def _map_topology(self, params: Dict[str, Any]) -> SkillResult:
        """Register systems and their dependencies in the topology graph."""
        systems_input = params.get("systems", [])
        dependencies_input = params.get("dependencies", [])

        if not systems_input and not dependencies_input:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Provide at least one of 'systems' or 'dependencies'."],
            )

        systems_added = 0
        systems_updated = 0
        deps_added = 0
        warnings: List[str] = []

        # Register systems
        for s in systems_input:
            sid = s.get("system_id")
            if not sid:
                warnings.append("Skipped system entry with no system_id.")
                continue

            sys_type = s.get("type", "service")
            if sys_type not in SYSTEM_TYPES:
                warnings.append(
                    f"System '{sid}' has unknown type '{sys_type}'; defaulting to 'service'."
                )
                sys_type = "service"

            criticality = s.get("criticality", "medium")
            if criticality not in CRITICALITY_LEVELS:
                criticality = "medium"

            record = {
                "system_id": sid,
                "name": s.get("name", sid),
                "type": sys_type,
                "criticality": criticality,
                "environment": s.get("environment", "production"),
                "owner_team": s.get("owner_team", "unknown"),
                "cloud_provider": s.get("cloud_provider", "aws"),
                "region": s.get("region", "us-east-1"),
                "tags": s.get("tags", {}),
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }

            if sid in self.systems:
                self.systems[sid].update(record)
                systems_updated += 1
            else:
                self.systems[sid] = record
                systems_added += 1

        # Register dependencies
        for d in dependencies_input:
            source = d.get("source")
            target = d.get("target")
            if not source or not target:
                warnings.append("Skipped dependency with missing source/target.")
                continue

            dep_type = d.get("type", "runtime")
            if dep_type not in DEPENDENCY_TYPES:
                warnings.append(
                    f"Dependency {source}->{target} has unknown type '{dep_type}'; "
                    f"defaulting to 'runtime'."
                )
                dep_type = "runtime"

            # Auto-register referenced systems if not present
            for node_id in (source, target):
                if node_id not in self.systems:
                    self.systems[node_id] = {
                        "system_id": node_id,
                        "name": node_id,
                        "type": "service",
                        "criticality": "medium",
                        "environment": "production",
                        "owner_team": "unknown",
                        "cloud_provider": "aws",
                        "region": "us-east-1",
                        "tags": {},
                        "registered_at": datetime.now(timezone.utc).isoformat(),
                    }

            edge = {
                "target": target,
                "type": dep_type,
                "latency_ms": d.get("latency_ms"),
                "is_critical": d.get("is_critical", False),
                "metadata": d.get("metadata", {}),
            }
            self.edges[source].append(edge)
            self.reverse_edges[target].append({
                "source": source,
                "type": dep_type,
                "is_critical": d.get("is_critical", False),
            })
            deps_added += 1

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "systems_added": systems_added,
                "systems_updated": systems_updated,
                "dependencies_added": deps_added,
                "total_systems": len(self.systems),
                "total_dependencies": sum(len(v) for v in self.edges.values()),
            },
            warnings=warnings,
        )

    # =====================================================================
    # get_dependencies
    # =====================================================================

    async def _get_dependencies(self, params: Dict[str, Any]) -> SkillResult:
        """Query upstream and downstream dependencies for a system."""
        system_id = params.get("system_id")
        if not system_id or system_id not in self.systems:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"System '{system_id}' not found in topology."],
            )

        direction = params.get("direction", "both")  # upstream, downstream, both
        depth = min(params.get("depth", 3), 10)

        downstream = []
        upstream = []

        if direction in ("downstream", "both"):
            downstream = self._bfs(system_id, self.edges, "target", depth)

        if direction in ("upstream", "both"):
            upstream = self._bfs(system_id, self.reverse_edges, "source", depth)

        system_info = self.systems[system_id]

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "system_id": system_id,
                "system_info": system_info,
                "downstream_dependencies": downstream,
                "upstream_dependencies": upstream,
                "downstream_count": len(downstream),
                "upstream_count": len(upstream),
            },
        )

    # =====================================================================
    # assess_blast_radius
    # =====================================================================

    async def _assess_blast_radius(self, params: Dict[str, Any]) -> SkillResult:
        """Calculate the blast radius for a change or incident on a system."""
        system_id = params.get("system_id")
        if not system_id or system_id not in self.systems:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"System '{system_id}' not found in topology."],
            )

        change_type = params.get("change_type", "outage")  # outage, degradation, config_change
        depth = min(params.get("depth", 5), 10)

        # Walk downstream to find all affected systems
        affected = self._bfs(system_id, self.edges, "target", depth)
        affected_ids = {a["system_id"] for a in affected}

        # Score impact
        criticality_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        impact_score = 0.0
        critical_systems: List[Dict[str, Any]] = []
        affected_teams: Set[str] = set()
        affected_environments: Set[str] = set()

        for aid in affected_ids:
            sys_info = self.systems.get(aid, {})
            crit = sys_info.get("criticality", "medium")
            weight = criticality_weights.get(crit, 2)
            impact_score += weight
            affected_teams.add(sys_info.get("owner_team", "unknown"))
            affected_environments.add(sys_info.get("environment", "unknown"))
            if crit in ("critical", "high"):
                critical_systems.append({
                    "system_id": aid,
                    "name": sys_info.get("name", aid),
                    "criticality": crit,
                    "owner_team": sys_info.get("owner_team", "unknown"),
                })

        # Normalise to 0-100
        max_possible = len(self.systems) * 4 if self.systems else 1
        normalized_score = min(round((impact_score / max_possible) * 100, 1), 100.0)

        # Severity classification
        if normalized_score >= 70 or len(critical_systems) >= 3:
            blast_severity = "critical"
        elif normalized_score >= 40 or len(critical_systems) >= 1:
            blast_severity = "high"
        elif normalized_score >= 15:
            blast_severity = "medium"
        else:
            blast_severity = "low"

        # Emit intelligence for high blast radius
        packets: List[IntelligencePacket] = []
        if blast_severity in ("critical", "high"):
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-BR-{system_id}-{uuid.uuid4().hex[:6]}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.INFRASTRUCTURE,
                    priority=Priority.CRITICAL if blast_severity == "critical" else Priority.HIGH,
                    confidence=85.0,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "system_id": system_id,
                        "blast_severity": blast_severity,
                        "affected_count": len(affected_ids),
                        "critical_systems_affected": len(critical_systems),
                        "change_type": change_type,
                    },
                    correlation_keys=[system_id, change_type],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "system_id": system_id,
                "change_type": change_type,
                "blast_severity": blast_severity,
                "impact_score": normalized_score,
                "affected_systems_count": len(affected_ids),
                "critical_systems_affected": critical_systems,
                "affected_teams": sorted(affected_teams),
                "affected_environments": sorted(affected_environments),
                "affected_systems": affected,
            },
            intelligence_packets=packets,
        )

    # =====================================================================
    # find_critical_paths
    # =====================================================================

    async def _find_critical_paths(self, params: Dict[str, Any]) -> SkillResult:
        """Identify critical dependency paths in the topology."""
        source_id = params.get("source_id")
        target_id = params.get("target_id")
        max_paths = min(params.get("max_paths", 5), 20)

        # If no source/target, find all paths between critical systems
        if not source_id and not target_id:
            return await self._find_all_critical_paths(max_paths)

        if source_id and source_id not in self.systems:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"Source system '{source_id}' not found."],
            )
        if target_id and target_id not in self.systems:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"Target system '{target_id}' not found."],
            )

        paths = self._find_paths_bfs(source_id, target_id, max_paths)

        scored_paths = []
        for path in paths:
            risk = self._score_path_risk(path)
            scored_paths.append({
                "path": path,
                "length": len(path),
                "risk_score": risk,
                "has_single_point_of_failure": self._has_spof(path),
            })

        scored_paths.sort(key=lambda p: p["risk_score"], reverse=True)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "source_id": source_id,
                "target_id": target_id,
                "paths_found": len(scored_paths),
                "paths": scored_paths[:max_paths],
            },
        )

    async def _find_all_critical_paths(self, max_paths: int) -> SkillResult:
        """Find paths between all pairs of critical systems."""
        critical_ids = [
            sid for sid, info in self.systems.items()
            if info.get("criticality") == "critical"
        ]

        if len(critical_ids) < 2:
            return SkillResult(
                success=True,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                data={
                    "critical_systems": critical_ids,
                    "paths_found": 0,
                    "paths": [],
                    "note": "Fewer than 2 critical systems; no paths to analyse.",
                },
            )

        all_paths = []
        for i, src in enumerate(critical_ids):
            for tgt in critical_ids[i + 1:]:
                paths = self._find_paths_bfs(src, tgt, 2)
                for p in paths:
                    risk = self._score_path_risk(p)
                    all_paths.append({
                        "source": src,
                        "target": tgt,
                        "path": p,
                        "length": len(p),
                        "risk_score": risk,
                        "has_single_point_of_failure": self._has_spof(p),
                    })

        all_paths.sort(key=lambda p: p["risk_score"], reverse=True)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "critical_systems": critical_ids,
                "paths_found": len(all_paths),
                "paths": all_paths[:max_paths],
            },
        )

    # =====================================================================
    # generate_report
    # =====================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive topology report."""
        report_type = params.get("report_type", "summary")  # summary, risk, ownership

        # Basic statistics
        total_systems = len(self.systems)
        total_deps = sum(len(v) for v in self.edges.values())

        criticality_dist: Dict[str, int] = defaultdict(int)
        type_dist: Dict[str, int] = defaultdict(int)
        team_dist: Dict[str, int] = defaultdict(int)
        env_dist: Dict[str, int] = defaultdict(int)

        for info in self.systems.values():
            criticality_dist[info.get("criticality", "medium")] += 1
            type_dist[info.get("type", "service")] += 1
            team_dist[info.get("owner_team", "unknown")] += 1
            env_dist[info.get("environment", "production")] += 1

        # Identify systems with high fan-in (many dependents = risky)
        fan_in: Dict[str, int] = defaultdict(int)
        for edges in self.reverse_edges.values():
            for e in edges:
                fan_in[e["source"]] += 1

        high_fan_in = sorted(
            [
                {"system_id": sid, "dependents": count, "name": self.systems.get(sid, {}).get("name", sid)}
                for sid, count in fan_in.items()
                if count >= 3
            ],
            key=lambda x: x["dependents"],
            reverse=True,
        )[:10]

        # Systems with no redundancy (single upstream dependency)
        single_dependency_systems = []
        for sid in self.systems:
            upstreams = self.reverse_edges.get(sid, [])
            if len(upstreams) == 1:
                single_dependency_systems.append({
                    "system_id": sid,
                    "name": self.systems[sid].get("name", sid),
                    "sole_dependency": upstreams[0]["source"],
                })

        # Risk summary
        critical_count = criticality_dist.get("critical", 0)
        risk_level = "high" if critical_count >= 3 or total_deps > total_systems * 3 else (
            "medium" if critical_count >= 1 else "low"
        )

        recommendations = []
        if single_dependency_systems:
            recommendations.append(
                f"{len(single_dependency_systems)} systems have a single point of dependency; "
                f"consider adding redundancy."
            )
        if high_fan_in:
            recommendations.append(
                f"{len(high_fan_in)} systems are high-fan-in hubs; prioritise their reliability."
            )
        if critical_count == 0 and total_systems > 0:
            recommendations.append("No systems are marked critical. Review criticality classifications.")

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "report_type": report_type,
                "summary": {
                    "total_systems": total_systems,
                    "total_dependencies": total_deps,
                    "risk_level": risk_level,
                },
                "distributions": {
                    "by_criticality": dict(criticality_dist),
                    "by_type": dict(type_dist),
                    "by_team": dict(team_dist),
                    "by_environment": dict(env_dist),
                },
                "risk_indicators": {
                    "high_fan_in_systems": high_fan_in,
                    "single_dependency_systems": single_dependency_systems[:10],
                },
                "recommendations": recommendations,
            },
        )

    # =====================================================================
    # Internal graph helpers
    # =====================================================================

    def _bfs(
        self,
        start: str,
        adjacency: Dict[str, List[Dict[str, Any]]],
        neighbor_key: str,
        max_depth: int,
    ) -> List[Dict[str, Any]]:
        """Breadth-first traversal returning discovered nodes with depth."""
        visited: Set[str] = {start}
        queue: deque = deque([(start, 0)])
        results: List[Dict[str, Any]] = []

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                neighbor = edge[neighbor_key]
                if neighbor not in visited:
                    visited.add(neighbor)
                    sys_info = self.systems.get(neighbor, {})
                    results.append({
                        "system_id": neighbor,
                        "name": sys_info.get("name", neighbor),
                        "criticality": sys_info.get("criticality", "medium"),
                        "depth": depth + 1,
                        "dependency_type": edge.get("type", "runtime"),
                    })
                    queue.append((neighbor, depth + 1))

        return results

    def _find_paths_bfs(
        self, source: str, target: str, max_paths: int,
    ) -> List[List[str]]:
        """Find up to max_paths shortest paths between source and target."""
        if source == target:
            return [[source]]

        paths: List[List[str]] = []
        queue: deque = deque([(source, [source])])
        visited_paths: Set[tuple] = set()

        while queue and len(paths) < max_paths:
            current, path = queue.popleft()
            if len(path) > 10:  # depth limit
                continue
            for edge in self.edges.get(current, []):
                neighbor = edge["target"]
                if neighbor in path:  # avoid cycles
                    continue
                new_path = path + [neighbor]
                path_key = tuple(new_path)
                if path_key in visited_paths:
                    continue
                visited_paths.add(path_key)
                if neighbor == target:
                    paths.append(new_path)
                else:
                    queue.append((neighbor, new_path))

        return paths

    def _score_path_risk(self, path: List[str]) -> float:
        """Score a path's risk based on criticality and length."""
        if not path:
            return 0.0
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total = 0.0
        for sid in path:
            crit = self.systems.get(sid, {}).get("criticality", "medium")
            total += weights.get(crit, 2)
        # Longer paths have more failure points
        return round(total * (1 + len(path) * 0.1), 2)

    def _has_spof(self, path: List[str]) -> bool:
        """Check if any node on the path is a single point of failure."""
        for sid in path[1:-1]:  # exclude endpoints
            # If the node has only one upstream and one downstream, it's a SPOF
            up = len(self.reverse_edges.get(sid, []))
            down = len(self.edges.get(sid, []))
            if up <= 1 and down <= 1:
                return True
        return False
