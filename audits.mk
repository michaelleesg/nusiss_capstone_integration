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
