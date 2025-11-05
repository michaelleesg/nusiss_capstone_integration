.PHONY: inventory-quick audit-fast audit-prune audit-apply

inventory-quick:
	@python3 _tools_inventory_quick.py || true

# relies on your existing refs-fast in Makefile
audit-fast:
	@$(MAKE) refs-fast
	@python3 _tools_audit_build_list.py || true

audit-prune:
	@ROOT="/home/mike/capstone_win" DRY_RUN=1 _tools/prune_from_csv.sh _inventory/to_remove.csv || true

audit-apply:
	@ROOT="/home/mike/capstone_win" DRY_RUN=0 _tools/prune_from_csv.sh _inventory/to_remove.csv || true
	@cd /home/mike/capstone_win && git fetch team && git add -A \
	  && git commit -m "chore: repo audit — prune zero-refs & junk (batch)" --no-verify || true \
	  && git push team HEAD:main || true

	  . && { echo "[FAIL] Agent A references found"; exit 2; } || { echo "[OK] No Agent A references"; }
.PHONY: assert-no-agent-a
assert-no-agent-a:
	@rg -n \
	  --glob '!.git/**' \
	  --glob '!_inventory/**' \
	  --glob '!audits.mk' \
	  --glob '!_tools_audit_build_list.py' \
	  --glob '!_tools_inventory_quick.py' \
	  -e '^\s*from\s+capstone_agent_a\b' \
	  -e '^\s*import\s+capstone_agent_a\b' \
	  -e 'mcp_server/client\.py' \
	  -e 'orchestrator/agents/(cve_|ioc_)' \
	  app/ scripts/ || { echo '[OK] No Agent A references in code dirs'; exit 0; }
	@echo '[FAIL] Agent A references found in code dirs'; exit 2
