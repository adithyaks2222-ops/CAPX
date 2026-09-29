# CAPX Architecture Rules

## 1. Data Flow Direction
**CLI / UI -> API Layer -> Core Analysis -> Detection -> Collectors -> OS**
* Upstream layers must never bypass the API to interact with collectors.
* Downstream layers (Collectors) must never be aware of upstream layers (UI).

## 2. Separation of Concerns
* **Flask/UI:** Presentation only. Zero cybersecurity logic.
* **Collectors:** Gather raw OS facts natively. No interpretation.
* **Analysis:** Interprets facts (e.g., "CPU usage is 90%").
* **Detection:** Correlates analyzed facts to identify indicators of compromise.
* **Risk:** Applies numerical scoring boundaries to findings.
* **Optimization:** Executes local state changes, strictly requiring explicit API approval.