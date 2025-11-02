\
    #!/usr/bin/env bash
    # repair_qdr_since_defaults_block_fixed.sh
    # WSL-safe, idempotent.
    # Moves param defaults to Make vars (?=) and rewrites qdr-since recipe
    # to call scripts/qdr_since.sh using $(VAR) — no $$, no shell ${...} in the recipe.
    # Also ensures a REAL TAB at the start of the recipe line.
    #
    # Takes care of:
    #  (1) converting any literal \t/TAB@@ mistakes into a real TAB in the new block,
    #  (2) avoiding single-quoted jq program cut-offs (handled in scripts/qdr_since.sh),
    #  (3) avoiding Make eating single $ (DR/OL/AG/AYS) by not using shell ${...} in the recipe,
    #  (4) avoiding $$→PID expansion by Bash by not using $$ in the recipe,
    #  (5) Make holds defaults via ?= and passes values as $(VAR) to the script.

    set +e  # WSL-safe: do not exit the shell on first error

    MAKEFILE="Makefile"
    START="### >>> HEVA PARAM START >>>"
    END="### <<< HEVA PARAM END <<<"

    if [ ! -f "$MAKEFILE" ]; then
      echo "❌ $MAKEFILE not found in $(pwd)"
      exit 1
    fi

    cp -f "$MAKEFILE" "${MAKEFILE}.bak.qdr_since_defaults_fixed" 2>/dev/null || true

    # ---------- 1) Ensure Make-level defaults via ?= (QDR/COL/TAG/DAYS) ----------
    need_qdr=0; need_col=0; need_tag=0; need_days=0
    grep -Eq '^[[:space:]]*QDR[[:space:]]*\?=' "$MAKEFILE" || need_qdr=1
    grep -Eq '^[[:space:]]*COL[[:space:]]*\?=' "$MAKEFILE" || need_col=1
    grep -Eq '^[[:space:]]*TAG[[:space:]]*\?=' "$MAKEFILE" || need_tag=1
    grep -Eq '^[[:space:]]*DAYS[[:space:]]*\?=' "$MAKEFILE" || need_days=1

    if [ $need_qdr -eq 1 ] || [ $need_col -eq 1 ] || [ $need_tag -eq 1 ] || [ $need_days -eq 1 ]; then
      tmp_insert="$(mktemp)"
      awk -v add_qdr="$need_qdr" -v add_col="$need_col" -v add_tag="$need_tag" -v add_days="$need_days" '
        BEGIN { inserted=0 }
        NR==1 { print; next }
        inserted==0 && $0 !~ /^[[:space:]]*(#|$)/ {
          if (add_qdr) print "QDR ?= http://127.0.0.1:6333"
          if (add_col) print "COL ?= heva_docs"
          if (add_tag) print "TAG ?= THREAT_ACTOR"
          if (add_days) print "DAYS ?= 7"
          inserted=1
          print
          next
        }
        { print }
        END {
          if (inserted==0) {
            if (add_qdr) print "QDR ?= http://127.0.0.1:6333"
            if (add_col) print "COL ?= heva_docs"
            if (add_tag) print "TAG ?= THREAT_ACTOR"
            if (add_days) print "DAYS ?= 7"
          }
        }
      ' "$MAKEFILE" > "$tmp_insert" && mv "$tmp_insert" "$MAKEFILE"
    fi

    # ---------- 2) Strip any existing HEVA PARAM block ----------
    tmp1="${MAKEFILE}.tmp.qdr_since_fixed_1"
    awk -v s="$START" -v e="$END" '
      BEGIN { skip=0 }
      index($0,s) { skip=1; next }
      index($0,e) { skip=0; next }
      !skip { print }
    ' "$MAKEFILE" > "$tmp1"

    # ---------- 3) Append a fresh, correct block with REAL TAB ----------
    tmp2="${MAKEFILE}.tmp.qdr_since_fixed_2"
    cat "$tmp1" > "$tmp2"
    {
      printf "%s\n" "$START"
      printf "%s\n" ".PHONY: qdr-since"
      printf "%s\n" "qdr-since:"
      # REAL TAB at the start of the recipe line:
      printf "\t%s\n" "@bash scripts/qdr_since.sh \"\$(QDR)\" \"\$(COL)\" \"\$(TAG)\" \"\$(DAYS)\""
      printf "%s\n" "$END"
    } >> "$tmp2"

    mv "$tmp2" "$MAKEFILE"
    rm -f "$tmp1"

    echo "✅ Rewrote qdr-since to use Make defaults and pass \$(QDR) \$(COL) \$(TAG) \$(DAYS)."
    echo "   Backup: ${MAKEFILE}.bak.qdr_since_defaults_fixed"
    echo
    echo "Sanity checks:"
    echo "  nl -ba Makefile | sed -n '/$START/,/$END/p'   # verify REAL TAB on recipe"
    echo "  make -n qdr-since                             # dry-run"
    echo
    echo "Run examples:"
    echo "  make qdr-since"
    echo "  make qdr-since DAYS=30"
    echo "  make qdr-since TAG=INDICATOR"
    echo "  make qdr-since COL=heva_docs QDR=http://127.0.0.1:6333"
