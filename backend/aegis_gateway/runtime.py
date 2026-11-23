"""Single source→ingest→detect→incident→response gateway runtime."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import queue
import threading
import time
from typing import Any, Iterator

from .config import Settings
from .detection import Decision, HybridDetector
from .energy import EnergyModel
from .iam import IAMService
from .policy import ResponseEngine
from .scenarios import CATALOGUE, generate_window
from .schema import TelemetryEvent
from .storage import GatewayStore, create_gateway_store


@dataclass
class SimulationState:
    scenario_id: str
    intensity: int
    started_at: float
    stop: threading.Event
    thread: threading.Thread
    windows: int = 0
    device_id: str | None = None


class GatewayRuntime:
    """Thread-safe runtime; no code path configures firewall/routing/NIC policy."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.settings.ensure_directories()
        self.store = create_gateway_store(self.settings)
        self.detector = HybridDetector(self.settings.model_path)
        self.energy = EnergyModel()
        self.iam = IAMService(storage=self.store, master_key=self.settings.device_master_key)
        self.response = ResponseEngine(
            self.settings.response_mode,
            self.settings.auto_response,
            in_process_enforcement=self.settings.in_process_enforcement,
        )
        self._subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._lock = threading.RLock()
        self._simulations: dict[str, SimulationState] = {}
        self._recent: deque[dict[str, Any]] = deque(maxlen=120)
        self._device_normal_streaks: dict[str, int] = defaultdict(int)
        self._reconstruct_enforcement_state()

    @property
    def _normal_streak(self) -> int:
        """Backward-compatible property: returns max streak across devices, or 0."""
        with self._lock:
            return max(self._device_normal_streaks.values(), default=0)

    @_normal_streak.setter
    def _normal_streak(self, value: int) -> None:
        """Backward-compatible setter: clears streaks if 0, or sets default."""
        with self._lock:
            if value == 0:
                self._device_normal_streaks.clear()
            else:
                self._device_normal_streaks["_default"] = value

    def reset_streaks(self) -> None:
        """Reset all per-device normal streaks."""
        with self._lock:
            self._device_normal_streaks.clear()

    def reset_simulation(self) -> None:
        """Reset runtime simulation and recovery streaks."""
        self.stop_simulation()
        self.reset_streaks()

    def _reconstruct_enforcement_state(self) -> None:
        """Reconstruct in-process policy enforcement state deterministically from persistent SQLite incidents upon startup."""
        try:
            all_incidents = self.store.incidents(limit=200)
            latest_by_device: dict[str, dict[str, Any]] = {}
            for inc in all_incidents:
                dev_id = inc.get("device_id")
                if not dev_id:
                    continue
                if dev_id not in latest_by_device:
                    latest_by_device[dev_id] = inc

            for dev_id, inc in latest_by_device.items():
                state = inc.get("lifecycle_state")
                if state not in {"RESPONDING", "CONTAINED", "RECOVERING"}:
                    continue

                act = inc.get("response_action") or "ISOLATE"
                severity = inc.get("severity", "HIGH")
                if state in {"RESPONDING", "CONTAINED"}:
                    if act in {"ISOLATE", "BLOCK"}:
                        self.response.isolate(
                            dev_id,
                            act,
                            "Reconstructed from persistent active incident",
                            state=state,
                            severity=severity,
                        )
                    elif act == "RATE_LIMIT":
                        self.response.set_rate_limit(dev_id)
                elif state == "RECOVERING":
                    if act in {"ISOLATE", "BLOCK"}:
                        self.response.isolate(
                            dev_id,
                            act,
                            "Reconstructed in recovering state",
                            state="RECOVERING",
                            severity=severity,
                        )
                    with self._lock:
                        self._device_normal_streaks[dev_id] = 3
        except Exception:
            pass

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        message = {"type": kind, "data": data}
        self._recent.append(message)
        with self._lock:
            stale: list[queue.Queue[dict[str, Any]]] = []
            for subscriber in self._subscribers:
                try: subscriber.put_nowait(message)
                except queue.Full: stale.append(subscriber)
            for subscriber in stale: self._subscribers.discard(subscriber)

    def subscribe(self) -> Iterator[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=100)
        with self._lock: self._subscribers.add(subscriber)
        try:
            yield {"type": "status", "data": self.status()}
            while True:
                try: yield subscriber.get(timeout=15)
                except queue.Empty: yield {"type": "keepalive", "data": {}}
        finally:
            with self._lock: self._subscribers.discard(subscriber)

    def configure_response(self, mode: str | None = None, auto: bool | None = None) -> dict[str, Any]:
        if mode is not None:
            self.response.mode = mode.upper()
        if auto is not None:
            self.response.auto = bool(auto)
        return {"mode": self.response.mode, "auto": self.response.auto}

    def ingest(self, event: TelemetryEvent | dict[str, Any]) -> dict[str, Any]:
        """Normalize and retain a source observation, returning evidence-backed result."""
        item = event if isinstance(event, TelemetryEvent) else TelemetryEvent.from_mapping(event)
        item.normalize()
        self.energy.correlate(item)

        dev_id = item.device_id or item.source_id
        is_enrolled = self.iam.is_enrolled_sensor(dev_id)
        auth_ok, auth_reason = self.iam.authenticate_device(
            dev_id,
            getattr(item, "auth_token", None),
            item.timestamp,
            item.flow_id,
        )

        is_impersonation = is_enrolled and not auth_ok

        # 1. IAM Authentication & Authorization resolution
        if is_impersonation:
            # Impersonation attempt against an enrolled sensor:
            # Deny access immediately without decaying the legitimate sensor's trust score.
            identity = self.iam.get(dev_id)
            delta = 0.0
            trust_reason = "unauthenticated impersonation attempt rejected; legitimate sensor trust preserved"
            access = {
                "identity": dev_id,
                "role": identity.role,
                "authentication_status": "FAILED_OR_UNVERIFIED",
                "mfa_status": identity.mfa_status,
                "authorization_status": "DENIED",
                "access_request": "gateway:telemetry",
                "decision": "DENY",
                "reason": f"Impersonation rejected: {auth_reason}",
            }
            # Impersonators must NOT activate or manipulate the legitimate sensor's mitigation state
            policy_decision = None
        elif not auth_ok and not is_enrolled:
            # Untrusted or unregistered source (e.g. ATK-01 or rogue device)
            identity = self.iam.get(dev_id)
            access = self.iam.access(identity.identity)
            access["authentication_status"] = "FAILED_OR_UNVERIFIED"
            access["authorization_status"] = "DENIED"
            access["decision"] = "DENY"
            access["reason"] = f"Unenrolled/unverified device access denied: {auth_reason}"
            policy_decision = self.response.evaluate(dev_id, item) if self.settings.in_process_enforcement else None
        else:
            # Authenticated device
            identity = self.iam.get(dev_id)
            access = self.iam.access(identity.identity)
            policy_decision = self.response.evaluate(dev_id, item) if self.settings.in_process_enforcement else None

        # 2. In-Process Policy Enforcement Boundary
        if self.settings.in_process_enforcement and self.response.mode in {"ACTIVE", "ENFORCING"} and policy_decision and policy_decision.drop:
            # Drop intercepted event at software boundary before detection ML inference
            # Preserves credential sanitization and audits drop in telemetry
            item.label = "ATTACK"
            item.confidence = 1.0
            item.model_version = self.detector.model_version
            item.feature_version = "window-features-v2"
            item.severity = policy_decision.metadata.get("severity", "HIGH")
            item.iam_identity, item.role = identity.identity, identity.role
            item.authentication_status = access["authentication_status"]
            item.authorization_status = access["authorization_status"]
            item.access_request = access["access_request"]
            item.access_decision = access["decision"]
            item.trust_score = identity.trust_score

            item.response_action = "DROP"
            item.response_mode = "SOFTWARE_INTERCEPT"
            item.lifecycle_state = "FILTERED"

            self.store.append_telemetry(item)
            self.store.record_iam(access)

            active = self.store.find_active_incident(device_id=dev_id)
            linked_alert = None
            inc_id = active["incident_id"] if active else None

            if active:
                alerts = self.store.list_alerts()
                linked_alerts = [a for a in alerts if a["incident_id"] == inc_id]
                if linked_alerts:
                    linked_alert = linked_alerts[0]

            self.store.record_action(
                event_id=item.event_id,
                incident_id=inc_id,
                action="DROP",
                reason=policy_decision.reason,
                policy="in-process-enforcement-v1",
                mode=self.response.mode,
                result="SOFTWARE_INTERCEPT",
            )

            filt_decision = Decision(
                prediction="ATTACK",
                confidence=1.0,
                severity=item.severity,
                evidence=[policy_decision.reason],
                score=1.0,
                supervised_prediction="ATTACK",
                anomaly_score=1.0,
                model_version=self.detector.model_version,
            )

            resp_dict = {
                "action": "DROP",
                "reason": policy_decision.reason,
                "mode": self.response.mode,
                "result": "SOFTWARE_INTERCEPT",
                "requires_incident": False,
                "enforced": True,
            }

            result = {
                "event": item.to_dict(),
                "decision": filt_decision.as_dict(),
                "response": resp_dict,
                "incident": active,
                "alert": linked_alert,
                "mitigation_enforced": True,
            }
            self.publish("telemetry", result)
            self.publish("response", {
                "incident_id": inc_id,
                "action": "DROP",
                "reason": policy_decision.reason,
                "mode": self.response.mode,
                "result": "SOFTWARE_INTERCEPT",
                "provenance": "SOFTWARE_INTERCEPT",
            })
            # IMPORTANT: Filtered events do NOT increment _normal_streak!
            return result

        # 3. Detection & ML Inference (Only executed when event is allowed)
        decision = self.detector.analyze(item)

        with self._lock:
            if is_impersonation:
                delta = 0.0
                trust_reason = "unauthenticated impersonation attempt rejected; legitimate sensor trust preserved"
            elif not auth_ok and not is_enrolled:
                identity, delta, trust_reason = self.iam.adjust_trust(
                    dev_id,
                    attack=decision.prediction == "ATTACK",
                    recovered=decision.prediction == "NORMAL",
                )
                access = self.iam.access(identity.identity)
                access["authentication_status"] = "FAILED_OR_UNVERIFIED"
                access["authorization_status"] = "DENIED"
                access["decision"] = "DENY"
                access["reason"] = f"Unenrolled/unverified device access denied: {auth_reason}"
            else:
                identity, delta, trust_reason = self.iam.adjust_trust(
                    dev_id,
                    attack=decision.prediction == "ATTACK",
                    recovered=decision.prediction == "NORMAL",
                )
                access = self.iam.access(identity.identity)

            item.label = decision.prediction
            item.confidence = decision.confidence
            item.model_version = decision.model_version
            item.feature_version = decision.feature_version
            item.severity = decision.severity
            item.iam_identity, item.role = identity.identity, identity.role
            item.authentication_status, item.authorization_status = access["authentication_status"], access["authorization_status"]
            item.access_request, item.access_decision, item.trust_score = access["access_request"], access["decision"], identity.trust_score
            plan = self.response.plan(item, decision)
            item.response_action, item.response_mode = plan.action, plan.mode
            item.lifecycle_state = "DETECTED" if plan.requires_incident else "OBSERVED"
            self.store.append_telemetry(item)
            self.store.record_iam(access)
            if delta:
                self.store.record_trust(identity.identity, identity.trust_score, delta, trust_reason)
                self.publish("trust", {"identity": identity.identity, "score": identity.trust_score, "delta": delta, "reason": trust_reason, "provenance": "DERIVED"})

            incident = None
            alert = None
            if plan.requires_incident:
                active = self.store.find_active_incident(device_id=item.device_id, attack_type=item.attack_type)
                if active:
                    incident = self.store.correlate_incident(
                        active["incident_id"],
                        item,
                        decision.evidence,
                        "Ongoing campaign correlated across observation windows"
                    )
                    if plan.mode != "MANUAL" and not is_impersonation:
                        self.response.apply_simulation(plan, item.device_id)
                else:
                    incident = self.store.create_incident(item, decision.evidence, "CPU/RAM/radio/energy are model-correlated")
                    self.publish("incident", incident)
                    if plan.mode != "MANUAL":
                        incident = self.store.transition_incident(
                            incident["incident_id"],
                            "TRIAGED",
                            "system",
                            "ML feature correlation and threat evidence analyzed.",
                            decision.evidence,
                        )
                        self.publish("incident", incident)
                        incident = self.store.transition_incident(
                            incident["incident_id"],
                            "RESPONDING",
                            "system",
                            "Simulated response planned; no host enforcement.",
                            decision.evidence,
                        )
                        self.publish("incident", incident)
                        if not is_impersonation:
                            self.response.apply_simulation(plan, item.device_id)
                        incident = self.store.transition_incident(
                            incident["incident_id"],
                            "CONTAINED",
                            "system",
                            "Containment state is simulated within the laboratory runtime.",
                            decision.evidence,
                        )
                        self.publish("incident", incident)
                alert = self.store.create_or_update_alert(incident, item, decision, plan)
                self.store.record_action(event_id=item.event_id, incident_id=incident["incident_id"], action=plan.action, reason=plan.reason, policy="hybrid-response-v1", mode=plan.mode, result=plan.result)
                if alert:
                    self.publish("alert", alert)
                self.publish("response", {"incident_id": incident["incident_id"], **plan.__dict__, "provenance": "SIMULATED"})
                if dev_id:
                    self._device_normal_streaks[dev_id] = 0
            else:
                if dev_id:
                    self._device_normal_streaks[dev_id] += 1
                self._verify_recovery(dev_id)
            result = {"event": item.to_dict(), "decision": decision.as_dict(), "response": plan.__dict__, "incident": incident, "alert": alert}
            self.publish("telemetry", result)
            return result

    def _verify_recovery(self, device_id: str | None = None) -> None:
        """Advance recovery only after actual consecutive normal observations for a specific device."""
        with self._lock:
            devices = [device_id] if device_id else list(self._device_normal_streaks.keys())
            for dev in devices:
                if not dev:
                    continue
                streak = self._device_normal_streaks.get(dev, 0)
                if streak < 3:
                    continue
                incident = self.store.find_active_incident(device_id=dev)
                if not incident:
                    continue
                state = incident.get("lifecycle_state")
                inc_id = incident.get("incident_id")
                try:
                    if state in {"CONTAINED", "RESPONDING", "DETECTED"}:
                        updated = self.store.transition_incident(
                            inc_id,
                            "RECOVERING",
                            "system",
                            f"Consecutive normal observations (streak={streak}) for device '{dev}' verified traffic/resource recovery.",
                            ["traffic returned toward modeled baseline"]
                        )
                        self.response.mark_recovering(dev)
                        self.publish("incident", updated)
                        alert = self.store.sync_alert_with_incident(updated)
                        if alert:
                            self.publish("alert", alert)
                    elif state == "RECOVERING" and streak >= 5:
                        self.response.release(dev)
                        self._device_normal_streaks.pop(dev, None)
                        updated = self.store.transition_incident(
                            inc_id,
                            "RESOLVED",
                            "system",
                            f"Recovery verified from sustained normal baseline ({streak} normal windows) for device '{dev}'.",
                            ["sustained normal observations verified"]
                        )
                        self.publish("incident", updated)
                        alert = self.store.sync_alert_with_incident(updated)
                        if alert:
                            self.publish("alert", alert)
                except (ValueError, KeyError):
                    continue

    def start_simulation(self, scenario_id: str, intensity: int = 3, duration: float | None = None, device_id: str | None = None) -> dict[str, Any]:
        """Start a bounded in-process profile; it sends no network traffic."""
        if scenario_id not in CATALOGUE:
            raise KeyError(f"Unknown scenario: {scenario_id}")
        if scenario_id in self._simulations:
            raise ValueError(f"Simulation already running: {scenario_id}")
        stop = threading.Event()
        state_ref: list[SimulationState] = []
        target_dev = device_id if device_id is not None else ("ATK-01" if scenario_id != "normal" else None)

        def run() -> None:
            sequence = 0
            started = time.monotonic()
            try:
                while not stop.is_set() and (duration is None or time.monotonic() - started < duration):
                    if device_id in {"ALL", "DDOS_CLUSTER"}:
                        active_count = max(1, min(6, intensity))
                        active_devs = [f"ATTACKER-0{k+1}" for k in range(active_count)]
                        cur_dev = active_devs[sequence % len(active_devs)]
                        result = self.ingest(generate_window(scenario_id, intensity, sequence, device_id=cur_dev))
                    else:
                        result = self.ingest(generate_window(scenario_id, intensity, sequence, device_id=device_id))
                    state_ref[0].windows += 1
                    sequence += 1
                    stop.wait(self.settings.demo_tick_seconds)
            finally:
                with self._lock: self._simulations.pop(scenario_id, None)
                self.publish("simulation", {"scenario_id": scenario_id, "state": "STOPPED", "windows": sequence, "provenance": "SIMULATED", "device_id": target_dev})

        thread = threading.Thread(target=run, name=f"aegis-{scenario_id}", daemon=True)
        state = SimulationState(scenario_id, max(1, min(intensity, 6)), time.time(), stop, thread, device_id=target_dev)
        state_ref.append(state)
        with self._lock: self._simulations[scenario_id] = state
        thread.start()
        payload = {"scenario_id": scenario_id, "intensity": state.intensity, "duration": duration, "state": "RUNNING", "provenance": "SIMULATED", "network_transmission": False, "device_id": target_dev}
        self.publish("simulation", payload)
        return payload

    def stop_simulation(self, scenario_id: str | None = None) -> list[str]:
        with self._lock:
            targets = [scenario_id] if scenario_id else list(self._simulations)
            states = [self._simulations[name] for name in targets if name in self._simulations]
        for state in states:
            state.stop.set()
        for state in states:
            if state.thread and state.thread.is_alive() and state.thread != threading.current_thread():
                state.thread.join(timeout=3.0)
        return [state.scenario_id for state in states]

    def step_device_recovery(self, device_id: str | None = None) -> list[dict[str, Any]]:
        """Generate strictly in-process recovery observation windows for quiescent contained devices."""
        with self._lock:
            if device_id:
                candidate_devs = [device_id]
            else:
                candidate_devs = list({
                    dev for dev, rec in self.response.enforcer.active_isolates.items()
                    if rec.get("state") in {"CONTAINED", "RECOVERING"}
                })
                try:
                    for inc in self.store.incidents(limit=50):
                        if inc.get("lifecycle_state") in {"CONTAINED", "RECOVERING"}:
                            d = inc.get("device_id")
                            if d and d not in candidate_devs:
                                candidate_devs.append(d)
                except Exception:
                    pass

            # Exclude any device currently associated with an active attack simulation
            active_attack_devices = {
                s.device_id
                for s in self._simulations.values()
                if s.scenario_id != "normal" and not s.stop.is_set() and s.device_id is not None
            }
            if active_attack_devices:
                candidate_devs = [d for d in candidate_devs if d not in active_attack_devices]

        results: list[dict[str, Any]] = []
        for dev in candidate_devs:
            with self._lock:
                rec = self.response.enforcer.active_isolates.get(dev)
                inc = self.store.find_active_incident(device_id=dev)
                state = rec.get("state") if rec else (inc.get("lifecycle_state") if inc else None)
                if state not in {"CONTAINED", "RECOVERING"}:
                    continue
                streak = self._device_normal_streaks.get(dev, 0)

            event = generate_window(
                "normal",
                intensity=1,
                sequence=streak,
                device_id=dev,
                provenance="SIMULATED",
                source_type="RECOVERY_OBSERVER",
            )
            res = self.ingest(event)
            results.append(res)
        return results

    def get_topology_attacker_states(self) -> list[dict[str, Any]]:
        """Return dynamic simulation, traffic indicator, and enforcement state for six DDoS attacker sources."""
        sims = getattr(self, "_simulations", {})
        active_sim = next((s for s in sims.values() if s.scenario_id != "normal" and not s.stop.is_set()), None)

        enforcer = getattr(self.response, "enforcer", None)
        active_isolates = getattr(enforcer, "active_isolates", {}) if enforcer else {}

        active_inc = self.store.find_active_incident()
        inc_state = active_inc.get("lifecycle_state") if active_inc else None
        inc_dev = active_inc.get("device_id") if active_inc else None

        # Threat is mitigated/contained if enforcer has isolates or incident is contained/recovering
        is_contained = inc_state in {"CONTAINED", "RECOVERING"} or len(active_isolates) > 0
        is_attack_running = active_sim is not None

        sim_scenario = active_sim.scenario_id if active_sim else (active_inc.get("attack_type") if active_inc else "udp_flood")
        sim_intensity = active_sim.intensity if active_sim else 3
        sim_target_dev = active_sim.device_id if active_sim else inc_dev

        attacker_defs = [
            {"id": "ATTACKER-01", "name": "ATTACKER-01", "ip": "10.42.0.250", "role": "UDP Flood Bot", "vector": "udp_flood", "alias": "ATK-01"},
            {"id": "ATTACKER-02", "name": "ATTACKER-02", "ip": "10.42.0.251", "role": "TCP SYN Bot", "vector": "syn_flood", "alias": None},
            {"id": "ATTACKER-03", "name": "ATTACKER-03", "ip": "10.42.0.252", "role": "ICMP Echo Bot", "vector": "icmp_flood", "alias": None},
            {"id": "ATTACKER-04", "name": "ATTACKER-04", "ip": "10.42.0.253", "role": "CoAP Anomaly Bot", "vector": "coap_anomaly", "alias": None},
            {"id": "ATTACKER-05", "name": "ATTACKER-05", "ip": "10.42.0.254", "role": "Slowloris Bot", "vector": "slow_rate", "alias": None},
            {"id": "ATTACKER-06", "name": "ATTACKER-06", "ip": "10.42.0.249", "role": "Modbus Exploit Bot", "vector": "modbus_anomaly", "alias": None},
        ]

        active_count = max(1, min(6, sim_intensity))

        results = []
        for i, a in enumerate(attacker_defs):
            node_id = a["id"]
            alias = a.get("alias")

            node_isolated = (node_id in active_isolates or (bool(alias) and alias in active_isolates))

            # Is this node participating in the configured attack?
            if sim_target_dev and sim_target_dev not in {None, "ATK-01", "ALL", "DDOS_CLUSTER"}:
                is_participating = (sim_target_dev in {node_id, alias})
            else:
                # Distributed multi-source DDoS attack:
                # Active bot sources scale 1:1 with simulation intensity (1 through 6)
                is_participating = (i < active_count)

            # Determine mitigation state:
            # 1. Device is directly isolated in the policy enforcer
            # 2. Or, the attack campaign this node is participating in has been contained/mitigated
            if node_isolated:
                is_mitigated = True
            elif is_contained and is_participating and (active_sim or inc_state in {"CONTAINED", "RECOVERING"}):
                # When specific device is isolated but no live multi-source simulation is active, isolate only targeted
                if (len(active_isolates) > 0 and not active_sim and not node_isolated):
                    is_mitigated = False
                else:
                    is_mitigated = True
            else:
                is_mitigated = False

            # Active attack flow: only when simulation is actively running AND node is not mitigated
            is_active = is_attack_running and is_participating and not is_mitigated

            # Trust score from IAM
            ident = self.iam.get(node_id)
            trust_score = ident.trust_score if ident else 35.0
            if alias:
                alias_ident = self.iam.get(alias)
                if alias_ident and alias_ident.trust_score < trust_score:
                    trust_score = alias_ident.trust_score

            if is_mitigated:
                status = "CONTAINED"
                flow_active = False
                packet_rate = 0.0
                traffic_ind = "BLOCKED (0.0 pps)"
            elif is_active:
                status = "ATTACKING"
                flow_active = True
                pps = round(max(15.0, 30.0 * (sim_intensity ** 1.3) / 3.0 + (i % 3) * 2.5), 1)
                packet_rate = pps
                traffic_ind = f"ACTIVE ({pps} pps)"
            else:
                status = "IDLE"
                flow_active = False
                packet_rate = 0.0
                traffic_ind = "IDLE (0.0 pps)"

            results.append({
                "id": node_id,
                "name": a["name"],
                "ip": a["ip"],
                "role": a["role"],
                "vector": a["vector"],
                "alias": alias,
                "status": status,
                "active": flow_active,
                "mitigated": is_mitigated,
                "packet_rate": packet_rate,
                "traffic_indicator": traffic_ind,
                "authorization": "DENIED",
                "trust": trust_score,
                "simulation_only": True,
            })
        return results

    def manual_action(self, incident_id: str, action: str, actor: str = "operator") -> dict[str, Any]:
        action = action.upper()
        if action not in {"ALERT", "BLOCK", "RATE_LIMIT", "ISOLATE", "RECOVER"}:
            raise ValueError("Unsupported response action")
        incident = self.store.incident(incident_id)
        if not incident: raise KeyError(f"Unknown incident: {incident_id}")
        dev_id = incident.get("device_id")
        if action == "RECOVER":
            if incident["lifecycle_state"] == "CONTAINED":
                incident = self.store.transition_incident(incident_id, "RECOVERING", actor, "Operator requested recovery verification; waiting for observable normal state.")
            self.response.mark_recovering(dev_id)
            result = "PENDING_OBSERVABLE_VERIFICATION"
        else:
            if incident["lifecycle_state"] in {"DETECTED", "TRIAGED"}:
                incident = self.store.transition_incident(incident_id, "RESPONDING", actor, f"Operator selected simulated {action}.")
            if incident["lifecycle_state"] == "RESPONDING":
                incident = self.store.transition_incident(incident_id, "CONTAINED", actor, "Manual containment is simulated; no host policy changed.")
            if dev_id:
                if action in {"ISOLATE", "BLOCK"}:
                    self.response.isolate(dev_id, action, f"Manual {action} requested by {actor}", state="CONTAINED")
                elif action == "RATE_LIMIT":
                    self.response.isolate(dev_id, "RATE_LIMIT", f"Manual RATE_LIMIT requested by {actor}", state="CONTAINED")
                    self.response.set_rate_limit(dev_id)
            result = "SIMULATED_NOT_ENFORCED"
        stored = self.store.record_action(event_id=incident["event_id"], incident_id=incident_id, action=action, reason="operator request", policy="manual-response-v1", mode="MANUAL", result=result)
        alert = self.store.sync_alert_with_incident(incident)
        self.publish("response", stored); self.publish("incident", incident)
        if alert:
            self.publish("alert", alert)
        return {"action": stored, "incident": incident, "alert": alert}

    def start_baseline(self, tick_seconds: float | None = None) -> bool:
        """Continuously generate legitimate baseline OT traffic windows when enabled."""
        if not self.settings.baseline_enabled:
            return False
        with self._lock:
            if hasattr(self, "_baseline_thread") and self._baseline_thread and self._baseline_thread.is_alive():
                return False
            self._baseline_stop = threading.Event()
            interval = tick_seconds or self.settings.demo_tick_seconds

            def run() -> None:
                sequence = 0
                stop_evt = self._baseline_stop
                while not stop_evt.is_set():
                    with self._lock:
                        has_active_attack_sims = any(
                            s.scenario_id != "normal" and not s.stop.is_set()
                            for s in self._simulations.values()
                        )
                    if not has_active_attack_sims:
                        try:
                            self.ingest(generate_window("normal", intensity=1, sequence=sequence))
                            sequence += 1
                        except Exception:
                            pass
                    try:
                        self.step_device_recovery()
                    except Exception:
                        pass
                    stop_evt.wait(interval)

            self._baseline_thread = threading.Thread(target=run, name="aegis-live-baseline", daemon=True)
            self._baseline_thread.start()
            return True

    def stop_baseline(self, timeout: float = 3.0) -> bool:
        """Stop the background baseline telemetry generator.

        Returns True if the worker is terminated or did not exist.
        Returns False if the worker remains alive after timeout.
        """
        with self._lock:
            stop_evt = getattr(self, "_baseline_stop", None)
            thread = getattr(self, "_baseline_thread", None)
            if stop_evt:
                stop_evt.set()

        if thread is None:
            return True

        if thread != threading.current_thread() and thread.is_alive():
            thread.join(timeout=timeout)

        with self._lock:
            if thread.is_alive():
                return False
            self._baseline_thread = None
            self._baseline_stop = None
            return True

    def status(self) -> dict[str, Any]:
        latest = self.store.telemetry(limit=1)
        return {
            "service": "AEGIS-OT laboratory gateway", "status": "ONLINE", "source_modes": ["SIMULATED", "SYNTHETIC", "REPLAYED", "MEASURED (opt-in capture)"],
            "response_mode": self.response.mode, "auto_response": self.response.auto, "host_enforcement": False,
            "latest": latest[-1] if latest else None, "active_simulations": [{"scenario_id": state.scenario_id, "intensity": state.intensity, "windows": state.windows, "device_id": state.device_id} for state in self._simulations.values()],
            "model_version": self.detector.model_version, "feature_version": "window-features-v2", "database": str(self.settings.database_path),
        }
