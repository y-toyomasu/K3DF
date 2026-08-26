"""Versioned, generic Defender capability ontology.

This module deliberately contains no Challenge-specific routes, credentials, flag
values, or attack instructions.  It only projects normalized evidence into a
read-only observation model.
"""

from copy import deepcopy


GRAPH_VERSION = "1.0"
NODE_STATUS = {"not_observed", "suspected", "confirmed"}
FLAG_SUBMISSION_STATUS = {"not_submitted", "detected", "accepted", "rejected"}

ONTOLOGY = (
    ("public_endpoint_reached", "Public Endpoint Reached", "access", 1),
    ("service_protocol_discovered", "Service / Protocol Discovered", "discovery", 2),
    ("exploit_attempt_observed", "Exploit Attempt Observed", "execution", 3),
    ("exploit_success_confirmed", "Exploit Success Confirmed", "execution", 4),
    ("application_data_access", "Application Data Access", "access", 5),
    ("credential_acquired", "Credential Acquired", "credential", 6),
    ("challenge_session_established", "Challenge Session Established", "session", 7),
    ("command_or_filesystem_read", "Command Execution / Filesystem Read", "execution", 8),
    ("internal_service_reached", "Internal Service Reached", "network", 9),
    ("challenge_database_access", "Challenge Database Access", "access", 10),
)


def _node(node_id, label, category, depth):
    return {"id": node_id, "label": label, "category": category, "depth": depth,
            "status": "not_observed", "confidence": 0.0, "evidence_ids": [],
            "first_observed_at": None, "last_observed_at": None}


def default_graph():
    return {"version": GRAPH_VERSION, "nodes": [_node(*definition) for definition in ONTOLOGY]}


def default_flag_objectives():
    return {"version": GRAPH_VERSION, "flags": [{"id": "flag_%s" % number, "label": "Flag %s" % number,
            "acquisition_status": "not_observed", "submission_status": "not_submitted",
            "evidence_ids": [], "updated_at": None, "provenance": "defender_estimate"}
            for number in (1, 2, 3)]}


def normalize_graph(value):
    graph = default_graph()
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), list):
        return graph
    known = {node["id"]: node for node in value["nodes"] if isinstance(node, dict) and node.get("id")}
    for node in graph["nodes"]:
        stored = known.get(node["id"], {})
        if stored.get("status") in NODE_STATUS:
            node["status"] = stored["status"]
        if isinstance(stored.get("confidence"), (int, float)):
            node["confidence"] = max(0.0, min(1.0, float(stored["confidence"])))
        if isinstance(stored.get("evidence_ids"), list):
            node["evidence_ids"] = list(dict.fromkeys(item for item in stored["evidence_ids"] if isinstance(item, str)))[:100]
        for field in ("first_observed_at", "last_observed_at"):
            if isinstance(stored.get(field), str):
                node[field] = stored[field]
    return graph


def normalize_flags(value):
    objectives = default_flag_objectives()
    if not isinstance(value, dict) or not isinstance(value.get("flags"), list):
        return objectives
    known = {flag.get("id"): flag for flag in value["flags"] if isinstance(flag, dict)}
    for flag in objectives["flags"]:
        stored = known.get(flag["id"], {})
        if stored.get("acquisition_status") in NODE_STATUS:
            flag["acquisition_status"] = stored["acquisition_status"]
        if stored.get("submission_status") in FLAG_SUBMISSION_STATUS:
            flag["submission_status"] = stored["submission_status"]
        if isinstance(stored.get("evidence_ids"), list):
            flag["evidence_ids"] = list(dict.fromkeys(item for item in stored["evidence_ids"] if isinstance(item, str)))[:100]
        if isinstance(stored.get("updated_at"), str):
            flag["updated_at"] = stored["updated_at"]
        if stored.get("provenance") in {"defender_estimate", "referee"}:
            flag["provenance"] = stored["provenance"]
    return objectives


def derived_depths(graph):
    nodes = normalize_graph(graph)["nodes"]
    confirmed = [node["depth"] for node in nodes if node["status"] == "confirmed"]
    possible = [node["depth"] for node in nodes if node["status"] in {"suspected", "confirmed"}]
    return {"confirmed_depth": max(confirmed, default=0), "possible_depth": max(possible, default=0),
            "confirmed_count": len(confirmed), "suspected_count": sum(node["status"] == "suspected" for node in nodes)}


def apply_observation(graph, node_id, evidence_id, timestamp, status="confirmed", confidence=1.0):
    graph = normalize_graph(graph)
    if status not in NODE_STATUS or status == "not_observed" or not isinstance(evidence_id, str):
        return graph
    node = next((item for item in graph["nodes"] if item["id"] == node_id), None)
    if not node or evidence_id in node["evidence_ids"]:
        return graph
    node["evidence_ids"].append(evidence_id)
    node["confidence"] = max(node["confidence"], max(0.0, min(1.0, float(confidence))))
    node["first_observed_at"] = node["first_observed_at"] or timestamp
    node["last_observed_at"] = timestamp
    if status == "confirmed" or node["status"] == "not_observed":
        node["status"] = status
    return graph


def apply_system_evidence(graph, evidence):
    metadata = evidence.get("metadata") or {}
    node_id = metadata.get("capability_node_id")
    status = metadata.get("capability_status", "confirmed")
    if not node_id:
        if evidence.get("source") == "nginx_access_log":
            node_id, status = "public_endpoint_reached", "confirmed"
        elif evidence.get("source") == "scanner_result":
            node_id, status = "exploit_attempt_observed", "suspected"
    if node_id:
        return apply_observation(graph, node_id, evidence.get("evidence_id"), evidence.get("timestamp"), status, evidence.get("confidence", 0.0))
    return normalize_graph(graph)


def apply_flag_evidence(objectives, evidence):
    objectives = normalize_flags(objectives)
    metadata = evidence.get("metadata") or {}
    flag_id = metadata.get("flag_id")
    evidence_id = evidence.get("evidence_id")
    flag = next((item for item in objectives["flags"] if item["id"] == flag_id), None)
    if not flag or not isinstance(evidence_id, str) or evidence_id in flag["evidence_ids"]:
        return objectives
    acquisition = metadata.get("flag_acquisition_status")
    submission = metadata.get("flag_submission_status")
    if acquisition in NODE_STATUS:
        # Detection alone is never confirmation.
        if acquisition == "confirmed" and metadata.get("flag_provenance") != "referee":
            acquisition = "suspected"
        flag["acquisition_status"] = acquisition if acquisition == "confirmed" or flag["acquisition_status"] == "not_observed" else flag["acquisition_status"]
    if submission in FLAG_SUBMISSION_STATUS:
        flag["submission_status"] = submission
        if submission == "accepted":
            flag["acquisition_status"] = "confirmed"
            flag["provenance"] = "referee"
        elif submission == "detected" and flag["acquisition_status"] == "not_observed":
            flag["acquisition_status"] = "suspected"
        elif submission == "rejected":
            flag["provenance"] = "referee"
    flag["evidence_ids"].append(evidence_id)
    flag["updated_at"] = evidence.get("timestamp")
    return objectives
