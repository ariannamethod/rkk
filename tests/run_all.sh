#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT_DIR/tests/lib.sh"

announce() {
    printf '\n== %s ==\n' "$1"
}

test_boot_init_and_help() {
    local case_dir
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    local db="$case_dir/kernel.db"
    capture_cmd help "$ROOT_DIR/kk"
    assert_exit help 1
    assert_contains "$case_dir/help.err" "Knowledge Kernel CLI"
    capture_cmd init "$ROOT_DIR/kk" init "$db"
    assert_exit init 0
    assert_contains "$case_dir/init.out" "initialized knowledge kernel"
    capture_cmd namespace_list_empty "$ROOT_DIR/kk" namespace-list "$db"
    assert_exit namespace_list_empty 0
    assert_contains "$case_dir/namespace_list_empty.out" $'namespace\tscope\towner_model'
    capture_cmd profiles "$ROOT_DIR/kk" profiles
    assert_exit profiles 0
    assert_contains "$case_dir/profiles.out" "profile=tiny"
    assert_contains "$case_dir/profiles.out" "profile=balanced"
    assert_contains "$case_dir/profiles.out" "profile=deep"
}

test_basic_namespace_and_model_cli() {
    local case_dir
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    local db="$case_dir/kernel.db"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    capture_cmd namespace_list "$ROOT_DIR/kk" namespace-list "$db"
    assert_exit namespace_list 0
    assert_contains "$case_dir/namespace_list.out" $'alpha\tpublic'
    "$ROOT_DIR/kk" attach-model "$db" model-public public alpha >/dev/null
    capture_cmd list_models "$ROOT_DIR/kk" list-models "$db"
    assert_exit list_models 0
    assert_contains "$case_dir/list_models.out" $'model-public\tpublic\talpha\tcompressed\tdeterministic-json-v1\tbalanced'
    capture_cmd inspect_model "$ROOT_DIR/kk" inspect-model "$db" model-public
    assert_exit inspect_model 0
    assert_json "$case_dir/inspect_model.out" model_name --equals model-public
    assert_json "$case_dir/inspect_model.out" query_profile_default --equals balanced
    assert_json "$case_dir/inspect_model.out" manifest_association.default_scope_manifest_found --equals true
}

test_ingest_reingest_and_lineage() {
    local case_dir file db docs
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    file="$docs/a.md"
    mkdir -p "$docs"
    cat > "$file" <<'DOC'
# Alpha
v1 alpha token.
DOC
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    capture_cmd ingest_v1 "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public
    assert_exit ingest_v1 0
    assert_contains "$case_dir/ingest_v1.out" "version=1"
    capture_cmd ingest_same "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public
    assert_exit ingest_same 0
    assert_contains "$case_dir/ingest_same.out" "skip unchanged"
    cat > "$file" <<'DOC'
# Alpha
v2 alpha token changed.
DOC
    capture_cmd ingest_v2 "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public
    assert_exit ingest_v2 0
    assert_contains "$case_dir/ingest_v2.out" "version=2"
    cat > "$file" <<'DOC'
# Alpha
v1 alpha token.
DOC
    capture_cmd ingest_reactivate "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public
    assert_exit ingest_reactivate 0
    assert_contains "$case_dir/ingest_reactivate.out" "reactivated lineage"
    capture_cmd inspect_document "$ROOT_DIR/kk" inspect-document "$db" "$file"
    assert_exit inspect_document 0
    assert_contains "$case_dir/inspect_document.out" "latest_version: 1"
    assert_contains "$case_dir/inspect_document.out" "total_versions: 2"
    capture_cmd document_history "$ROOT_DIR/kk" document-history "$db" "$file"
    assert_exit document_history 0
    assert_contains "$case_dir/document_history.out" $'1\t'
    assert_contains "$case_dir/document_history.out" $'2\t'
    assert_contains "$case_dir/document_history.out" $'	true	initial ingest'
}

test_namespace_manifest_and_scope_errors() {
    local case_dir db docs
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    mkdir -p "$docs"
    printf '# Alpha\nmanifest token\n' > "$docs/a.md"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    capture_cmd invalid_scope "$ROOT_DIR/kk" namespace-set "$db" alpha internal nope
    assert_exit invalid_scope 1
    assert_contains "$case_dir/invalid_scope.err" "invalid scope 'internal'"
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    capture_cmd scope_mismatch "$ROOT_DIR/kk" namespace-set "$db" alpha shared:team "bad"
    assert_exit scope_mismatch 1
    assert_contains "$case_dir/scope_mismatch.err" "namespace scope mismatch"
    "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" good public alpha >/dev/null
    capture_cmd attach_wrong "$ROOT_DIR/kk" attach-model "$db" wrong private:wrong alpha
    assert_exit attach_wrong 1
    assert_contains "$case_dir/attach_wrong.err" "namespace scope mismatch"
    capture_cmd namespace_stats_ok "$ROOT_DIR/kk" namespace-stats "$db" alpha public
    assert_exit namespace_stats_ok 0
    assert_contains "$case_dir/namespace_stats_ok.out" "namespace: alpha"
    capture_cmd namespace_stats_bad_scope "$ROOT_DIR/kk" namespace-stats "$db" alpha shared:team
    assert_exit namespace_stats_bad_scope 1
    assert_contains "$case_dir/namespace_stats_bad_scope.err" "namespace manifest missing"
}

test_attach_model_missing_namespace_rejected() {
    local case_dir db
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    capture_cmd attach_missing "$ROOT_DIR/kk" attach-model "$db" ghost public missing
    assert_exit attach_missing 1
    assert_contains "$case_dir/attach_missing.err" "namespace manifest missing: namespace=missing scope=public"
    capture_cmd list_models "$ROOT_DIR/kk" list-models "$db"
    assert_exit list_models 0
    assert_not_contains "$case_dir/list_models.out" $'ghost\t'
    capture_cmd model_history "$ROOT_DIR/kk" model-history "$db" ghost
    assert_exit model_history 0
    assert_not_contains "$case_dir/model_history.out" $'\tattach\t'
}

test_attach_model_scope_contract_rejected() {
    local case_dir db
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    capture_cmd attach_mismatch "$ROOT_DIR/kk" attach-model "$db" model-a private:model-a alpha
    assert_exit attach_mismatch 1
    assert_contains "$case_dir/attach_mismatch.err" "namespace scope mismatch: namespace=alpha manifest_scope=public requested=private:model-a"
    capture_cmd list_models "$ROOT_DIR/kk" list-models "$db"
    assert_exit list_models 0
    assert_not_contains "$case_dir/list_models.out" $'model-a\t'
    capture_cmd model_history "$ROOT_DIR/kk" model-history "$db" model-a
    assert_exit model_history 0
    assert_not_contains "$case_dir/model_history.out" $'\tattach\t'
}

test_update_model_scope_contract_rejected() {
    local case_dir db
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" model-a public alpha >/dev/null
    capture_cmd update_mismatch "$ROOT_DIR/kk" update-model "$db" model-a private:model-a alpha
    assert_exit update_mismatch 1
    assert_contains "$case_dir/update_mismatch.err" "namespace scope mismatch: namespace=alpha manifest_scope=public requested=private:model-a"
    capture_cmd inspect_model "$ROOT_DIR/kk" inspect-model "$db" model-a
    assert_exit inspect_model 0
    assert_json "$case_dir/inspect_model.out" scope_default --equals public
    assert_json "$case_dir/inspect_model.out" namespace_default --equals alpha
    capture_cmd model_history "$ROOT_DIR/kk" model-history "$db" model-a
    assert_exit model_history 0
    assert_not_contains "$case_dir/model_history.out" $'\tupdate\t'
}

test_model_lifecycle_append_only() {
    local case_dir db
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" model-public public alpha >/dev/null
    "$ROOT_DIR/kk" update-model "$db" model-public public alpha >/dev/null
    "$ROOT_DIR/kk" model-set-profile "$db" model-public deep >/dev/null
    capture_cmd inspect_before_detach "$ROOT_DIR/kk" inspect-model "$db" model-public
    assert_exit inspect_before_detach 0
    assert_json "$case_dir/inspect_before_detach.out" query_profile_default --equals deep
    "$ROOT_DIR/kk" detach-model "$db" model-public >/dev/null
    capture_cmd model_history "$ROOT_DIR/kk" model-history "$db" model-public
    assert_exit model_history 0
    assert_contains "$case_dir/model_history.out" $'attach'
    assert_contains "$case_dir/model_history.out" $'update'
    assert_contains "$case_dir/model_history.out" $'profile'
    assert_contains "$case_dir/model_history.out" $'detach'
    capture_cmd inspect_after_detach "$ROOT_DIR/kk" inspect-model "$db" model-public
    assert_exit inspect_after_detach 1
    assert_contains "$case_dir/inspect_after_detach.err" "not attached"
}

test_ask_success_zero_hit_and_manifest_errors() {
    local case_dir db docs file
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    file="$docs/alpha.md"
    mkdir -p "$docs"
    python3 - <<'PY' "$file"
from pathlib import Path
p = Path(__import__('sys').argv[1])
text = '# Alpha\n' + ('kernel lineage provenance token ' * 60) + '\n'
p.write_text(text)
PY
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" model-public public alpha >/dev/null
    capture_cmd ask_ok "$ROOT_DIR/kk" ask "$db" model-public "kernel lineage provenance token" 5
    assert_exit ask_ok 0
    assert_json "$case_dir/ask_ok.out" packet_schema_version --equals kk.packet.v2
    assert_json "$case_dir/ask_ok.out" ask_schema_version --equals kk.ask.v2
    assert_json "$case_dir/ask_ok.out" resolution_trace.hit_scope --equals public
    assert_json "$case_dir/ask_ok.out" resolution_trace.fallback_to_public --equals false
    assert_json "$case_dir/ask_ok.out" results --type list
    assert_json "$case_dir/ask_ok.out" budgeting.applied --equals true
    capture_cmd ask_zero "$ROOT_DIR/kk" ask "$db" model-public "nonesuchtoken" 5
    assert_exit ask_zero 2
    assert_json "$case_dir/ask_zero.out" error.code --equals no_matches
    assert_json "$case_dir/ask_zero.out" resolution_trace.zero_hit_all_stages --equals true
    assert_json "$case_dir/ask_zero.out" budgeting.applied --equals false

    local db_missing="$case_dir/missing.db"
    "$ROOT_DIR/kk" init "$db_missing" >/dev/null
    python3 - <<'PY' "$db_missing"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute(
    "INSERT INTO model_registry(model_name, scope_default, namespace_default, retrieval_mode_default, packet_mode_default, query_profile_default, is_active, created_ts, updated_ts) "
    "VALUES(?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    ("model-missing", "public", "ghost", "compressed", "deterministic-json-v1", "balanced"),
)
db.commit()
db.close()
PY
    capture_cmd ask_manifest_missing "$ROOT_DIR/kk" ask "$db_missing" model-missing "ghost token" 5
    assert_exit ask_manifest_missing 2
    assert_json "$case_dir/ask_manifest_missing.out" error.code --equals namespace_manifest_missing
    assert_json "$case_dir/ask_manifest_missing.out" budgeting.applied --equals false
}

test_public_fallback_traceability() {
    local case_dir db docs_shared docs_public
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs_shared="$case_dir/shared"
    docs_public="$case_dir/public"
    mkdir -p "$docs_shared" "$docs_public"
    printf '# Shared\nshared token\n' > "$docs_shared/s.md"
    printf '# Public\npublic fallback token\n' > "$docs_public/p.md"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha shared:team "Alpha shared" >/dev/null
    "$ROOT_DIR/kk" ingest "$db" "$docs_shared" alpha shared:team >/dev/null
    capture_cmd setup_public_manifest "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public"
    assert_exit setup_public_manifest 1
    assert_contains "$case_dir/setup_public_manifest.err" "namespace scope mismatch"
    "$ROOT_DIR/kk" attach-model "$db" team-model shared:team alpha >/dev/null
    capture_cmd ask_shared "$ROOT_DIR/kk" ask "$db" team-model "shared token" 5
    assert_exit ask_shared 0
    assert_json "$case_dir/ask_shared.out" resolution_trace.fallback_to_public --equals false
    assert_json "$case_dir/ask_shared.out" resolution_trace.hit_scope --equals shared:team
    assert_json "$case_dir/ask_shared.out" resolution_trace.searched_scopes --len 1
    assert_json "$case_dir/ask_shared.out" resolution_trace.searched_scopes.0 --equals shared:team
}

test_query_profiles_and_budgeting() {
    local case_dir db docs
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    mkdir -p "$docs"
    python3 - <<'PY' "$docs"
from pathlib import Path
root = Path(__import__('sys').argv[1])
for idx in range(1, 8):
    text = f"# Doc {idx}\n" + ((f"signal-{idx} kernel lineage provenance budget token section {idx} " * 40) + "\n")
    (root / f"doc_{idx}.md").write_text(text)
PY
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" profiler public alpha >/dev/null

    capture_cmd ask_balanced "$ROOT_DIR/kk" ask "$db" profiler "kernel lineage provenance budget token" 9
    assert_exit ask_balanced 0
    assert_json "$case_dir/ask_balanced.out" query_profile --equals balanced
    assert_json "$case_dir/ask_balanced.out" budgeting.requested_top_k --equals 9
    assert_json "$case_dir/ask_balanced.out" budgeting.profile_result_cap --equals 4
    assert_json "$case_dir/ask_balanced.out" budgeting.returned_result_count --equals 4
    assert_json "$case_dir/ask_balanced.out" budgeting.result_truncated --equals true
    assert_json "$case_dir/ask_balanced.out" budgeting.any_truncation --equals true
    assert_json "$case_dir/ask_balanced.out" results.0.text_truncated --equals true
    assert_json "$case_dir/ask_balanced.out" results.0.lineage_summary_truncated --equals false
    assert_json "$case_dir/ask_balanced.out" results.0.trust_provenance.summary_truncated --equals false

    "$ROOT_DIR/kk" model-set-profile "$db" profiler tiny >/dev/null
    capture_cmd ask_tiny "$ROOT_DIR/kk" ask "$db" profiler "kernel lineage provenance budget token" 9
    assert_exit ask_tiny 0
    assert_json "$case_dir/ask_tiny.out" query_profile --equals tiny
    assert_json "$case_dir/ask_tiny.out" budgeting.returned_result_count --equals 2
    assert_json "$case_dir/ask_tiny.out" results.0.structure.included --equals false
    assert_json "$case_dir/ask_tiny.out" results.0.score_breakdown.included --equals false

    "$ROOT_DIR/kk" model-set-profile "$db" profiler deep >/dev/null
    capture_cmd ask_deep "$ROOT_DIR/kk" ask "$db" profiler "kernel lineage provenance budget token" 9
    assert_exit ask_deep 0
    assert_json "$case_dir/ask_deep.out" query_profile --equals deep
    assert_json "$case_dir/ask_deep.out" budgeting.returned_result_count --equals 6
    assert_json "$case_dir/ask_deep.out" results.0.structure.included --equals true
    assert_json "$case_dir/ask_deep.out" results.0.adjacent_context.included --equals true
    assert_json "$case_dir/ask_deep.out" budgeting.applied --equals true
}

test_integrity_rebuild_and_damage_detection() {
    local case_dir db docs
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    mkdir -p "$docs"
    printf '# Integrity\nfts token\n' > "$docs/a.md"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public >/dev/null
    capture_cmd integrity_ok "$ROOT_DIR/kk" check-integrity "$db"
    assert_exit integrity_ok 0
    assert_contains "$case_dir/integrity_ok.out" "summary=PASS issues=0"
    python3 - <<'PY' "$db"
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute('DELETE FROM chunk_fts;')
con.commit()
con.close()
PY
    capture_cmd integrity_fail "$ROOT_DIR/kk" check-integrity "$db"
    assert_exit integrity_fail 2
    assert_contains "$case_dir/integrity_fail.out" "latest_chunks_missing_fts status=FAIL count=1"
    capture_cmd rebuild "$ROOT_DIR/kk" rebuild-fts "$db"
    assert_exit rebuild 0
    assert_contains "$case_dir/rebuild.out" "rebuild-fts complete"
    capture_cmd integrity_restored "$ROOT_DIR/kk" check-integrity "$db"
    assert_exit integrity_restored 0
    assert_contains "$case_dir/integrity_restored.out" "summary=PASS issues=0"
}

test_edge_cases_and_missing_targets() {
    local case_dir db docs empty weird
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    empty="$case_dir/empty"
    weird="$docs/sub dir/odd [name] ü.md"
    mkdir -p "$docs/sub dir" "$empty"
    printf 'x\n' > "$docs/tiny.txt"
    printf 'Plain paragraph without heading but with kernel token.\n' > "$docs/plain.md"
    printf '# Weird\nweird path token\n' > "$weird"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    capture_cmd ingest_empty "$ROOT_DIR/kk" ingest "$db" "$empty" alpha public
    assert_exit ingest_empty 0
    assert_contains "$case_dir/ingest_empty.out" "ingest complete: 0 file(s) updated"
    capture_cmd ingest_docs "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public
    assert_exit ingest_docs 0
    capture_cmd ingest_dupe "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public
    assert_exit ingest_dupe 0
    assert_contains "$case_dir/ingest_dupe.out" "skip unchanged"
    capture_cmd inspect_weird "$ROOT_DIR/kk" inspect-document "$db" "$weird"
    assert_exit inspect_weird 0
    assert_contains "$case_dir/inspect_weird.out" "document_path: $weird"
    capture_cmd history_missing "$ROOT_DIR/kk" document-history "$db" "$case_dir/missing.md"
    assert_exit history_missing 1
    assert_contains "$case_dir/history_missing.err" "document not found:"
    "$ROOT_DIR/kk" attach-model "$db" edge public alpha >/dev/null
    "$ROOT_DIR/kk" detach-model "$db" edge >/dev/null
    capture_cmd ask_detached "$ROOT_DIR/kk" ask "$db" edge "kernel" 5
    assert_exit ask_detached 1
    assert_json "$case_dir/ask_detached.out" error.code --equals model_not_attached
    local db_zero="$case_dir/zero.db"
    "$ROOT_DIR/kk" init "$db_zero" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db_zero" emptyspace public "Empty manifest" >/dev/null
    capture_cmd stats_zero_docs "$ROOT_DIR/kk" namespace-stats "$db_zero" emptyspace public
    assert_exit stats_zero_docs 0
    assert_contains "$case_dir/stats_zero_docs.out" "document_count: 0"
}

setup_contract_fixture() {
    local case_dir=$1
    local db="$case_dir/kernel.db"
    local docs="$case_dir/docs"
    mkdir -p "$docs"
    cat > "$docs/alpha.md" <<'DOC'
# Alpha Kernel
kernel contract deterministic lineage provenance anchor signal.

This document exists to stabilize the kernel contract surface.
DOC
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" model-public public alpha >/dev/null
}

test_contract_golden_outputs() {
    local case_dir db docs file
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    file="$docs/alpha.md"

    setup_contract_fixture "$case_dir"

    capture_cmd ask_success "$ROOT_DIR/kk" ask "$db" model-public "kernel contract deterministic lineage" 5
    assert_exit ask_success 0
    assert_golden ask_success json tests/golden/ask_success.json
    assert_json "$case_dir/ask_success.out" packet_schema_version --equals kk.packet.v2
    assert_json "$case_dir/ask_success.out" ask_schema_version --equals kk.ask.v2

    capture_cmd ask_zero_hit "$ROOT_DIR/kk" ask "$db" model-public "nonesuchtoken" 5
    assert_exit ask_zero_hit 2
    assert_golden ask_zero_hit json tests/golden/ask_zero_hit.json
    assert_json "$case_dir/ask_zero_hit.out" packet_schema_version --equals kk.packet.v2
    assert_json "$case_dir/ask_zero_hit.out" ask_schema_version --equals kk.ask.v2

    capture_cmd inspect_model_golden "$ROOT_DIR/kk" inspect-model "$db" model-public
    assert_exit inspect_model_golden 0
    assert_golden inspect_model_golden json tests/golden/inspect_model.json

    capture_cmd inspect_document_golden "$ROOT_DIR/kk" inspect-document "$db" "$file"
    assert_exit inspect_document_golden 0
    assert_golden inspect_document_golden text tests/golden/inspect_document.txt

    capture_cmd integrity_pass_golden "$ROOT_DIR/kk" check-integrity "$db"
    assert_exit integrity_pass_golden 0
    assert_golden integrity_pass_golden text tests/golden/check_integrity_pass.txt

    python3 - <<'PY' "$db"
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("DELETE FROM chunk_fts;")
con.commit()
con.close()
PY
    capture_cmd integrity_fail_golden "$ROOT_DIR/kk" check-integrity "$db"
    assert_exit integrity_fail_golden 2
    assert_golden integrity_fail_golden text tests/golden/check_integrity_fts_fail.txt
}

test_contract_determinism() {
    local case_dir db docs file
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    file="$docs/alpha.md"

    setup_contract_fixture "$case_dir"

    capture_cmd ask_first "$ROOT_DIR/kk" ask "$db" model-public "kernel contract deterministic lineage" 5
    capture_cmd ask_second "$ROOT_DIR/kk" ask "$db" model-public "kernel contract deterministic lineage" 5
    assert_exit ask_first 0
    assert_exit ask_second 0
    assert_repeatable_output ask_first ask_second json

    capture_cmd inspect_model_first "$ROOT_DIR/kk" inspect-model "$db" model-public
    capture_cmd inspect_model_second "$ROOT_DIR/kk" inspect-model "$db" model-public
    assert_exit inspect_model_first 0
    assert_exit inspect_model_second 0
    assert_repeatable_output inspect_model_first inspect_model_second json

    capture_cmd inspect_document_first "$ROOT_DIR/kk" inspect-document "$db" "$file"
    capture_cmd inspect_document_second "$ROOT_DIR/kk" inspect-document "$db" "$file"
    assert_exit inspect_document_first 0
    assert_exit inspect_document_second 0
    assert_repeatable_output inspect_document_first inspect_document_second text

    capture_cmd profiles_first "$ROOT_DIR/kk" profiles
    capture_cmd profiles_second "$ROOT_DIR/kk" profiles
    assert_exit profiles_first 0
    assert_exit profiles_second 0
    assert_repeatable_output profiles_first profiles_second text
}

test_negative_contract_failures() {
    local case_dir db docs file db_stale
    CURRENT_CASE_DIR=$(new_case_dir)
    case_dir=$CURRENT_CASE_DIR
    db="$case_dir/kernel.db"
    docs="$case_dir/docs"
    file="$docs/alpha.md"
    db_stale="$case_dir/stale.db"

    mkdir -p "$docs"
    printf '# Alpha\nkernel contract token\n' > "$file"
    "$ROOT_DIR/kk" init "$db" >/dev/null
    "$ROOT_DIR/kk" namespace-set "$db" alpha public "Alpha public" >/dev/null
    "$ROOT_DIR/kk" ingest "$db" "$docs" alpha public >/dev/null
    "$ROOT_DIR/kk" attach-model "$db" model-public public alpha >/dev/null

    capture_cmd attach_missing_manifest "$ROOT_DIR/kk" attach-model "$db" ghost public missing
    assert_exit attach_missing_manifest 1
    assert_file_exact "$case_dir/attach_missing_manifest.err" "namespace manifest missing: namespace=missing scope=public"

    capture_cmd attach_scope_mismatch "$ROOT_DIR/kk" attach-model "$db" ghost private:ghost alpha
    assert_exit attach_scope_mismatch 1
    assert_file_exact "$case_dir/attach_scope_mismatch.err" "namespace scope mismatch: namespace=alpha manifest_scope=public requested=private:ghost"

    capture_cmd update_missing_manifest "$ROOT_DIR/kk" update-model "$db" model-public public missing
    assert_exit update_missing_manifest 1
    assert_file_exact "$case_dir/update_missing_manifest.err" "namespace manifest missing: namespace=missing scope=public"

    capture_cmd update_scope_mismatch "$ROOT_DIR/kk" update-model "$db" model-public private:model-public alpha
    assert_exit update_scope_mismatch 1
    assert_file_exact "$case_dir/update_scope_mismatch.err" "namespace scope mismatch: namespace=alpha manifest_scope=public requested=private:model-public"

    "$ROOT_DIR/kk" detach-model "$db" model-public >/dev/null
    capture_cmd ask_detached_contract "$ROOT_DIR/kk" ask "$db" model-public "kernel" 5
    assert_exit ask_detached_contract 1
    assert_json "$case_dir/ask_detached_contract.out" error.code --equals model_not_attached
    assert_json "$case_dir/ask_detached_contract.out" packet_schema_version --equals kk.packet.v2
    assert_json "$case_dir/ask_detached_contract.out" ask_schema_version --equals kk.ask.v2

    "$ROOT_DIR/kk" init "$db_stale" >/dev/null
    python3 - <<'PY' "$db_stale"
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute(
    "INSERT INTO model_registry(model_name, scope_default, namespace_default, retrieval_mode_default, packet_mode_default, query_profile_default, is_active, created_ts, updated_ts) "
    "VALUES(?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    ("stale-model", "public", "ghost", "compressed", "deterministic-json-v1", "balanced"),
)
con.commit()
con.close()
PY
    capture_cmd ask_stale_registry "$ROOT_DIR/kk" ask "$db_stale" stale-model "ghost token" 5
    assert_exit ask_stale_registry 2
    assert_json "$case_dir/ask_stale_registry.out" error.code --equals namespace_manifest_missing
    assert_json "$case_dir/ask_stale_registry.out" budgeting.applied --equals false

    capture_cmd inspect_document_missing "$ROOT_DIR/kk" inspect-document "$db" "$case_dir/missing.md"
    assert_exit inspect_document_missing 1
    assert_file_exact "$case_dir/inspect_document_missing.err" "document not found: $case_dir/missing.md"

    capture_cmd namespace_stats_missing_manifest "$ROOT_DIR/kk" namespace-stats "$db" missing public
    assert_exit namespace_stats_missing_manifest 1
    assert_file_exact "$case_dir/namespace_stats_missing_manifest.err" "namespace manifest missing: namespace=missing scope=public"

    capture_cmd namespace_stats_scope_mismatch "$ROOT_DIR/kk" namespace-stats "$db" alpha shared:team
    assert_exit namespace_stats_scope_mismatch 1
    assert_file_exact "$case_dir/namespace_stats_scope_mismatch.err" "namespace manifest missing: namespace=alpha scope=shared:team"
}

main() {
    announce "compile"
    compile_kernel
    init_harness
    trap cleanup_harness EXIT

    announce "boot / init / basic cli"
    run_test "boot_init_and_help" test_boot_init_and_help
    run_test "basic_namespace_and_model_cli" test_basic_namespace_and_model_cli

    announce "ingest / lineage"
    run_test "ingest_reingest_and_lineage" test_ingest_reingest_and_lineage

    announce "namespace / scope discipline"
    run_test "namespace_manifest_and_scope_errors" test_namespace_manifest_and_scope_errors
    run_test "attach_model_missing_namespace_rejected" test_attach_model_missing_namespace_rejected
    run_test "attach_model_scope_contract_rejected" test_attach_model_scope_contract_rejected

    announce "model lifecycle"
    run_test "update_model_scope_contract_rejected" test_update_model_scope_contract_rejected
    run_test "model_lifecycle_append_only" test_model_lifecycle_append_only

    announce "ask contract"
    run_test "ask_success_zero_hit_and_manifest_errors" test_ask_success_zero_hit_and_manifest_errors
    run_test "public_fallback_traceability" test_public_fallback_traceability

    announce "profiles / budgeting"
    run_test "query_profiles_and_budgeting" test_query_profiles_and_budgeting

    announce "observability / maintenance"
    run_test "integrity_rebuild_and_damage_detection" test_integrity_rebuild_and_damage_detection

    announce "regression / edge cases"
    run_test "edge_cases_and_missing_targets" test_edge_cases_and_missing_targets

    announce "step 9 / contract hardening"
    run_test "contract_golden_outputs" test_contract_golden_outputs
    run_test "contract_determinism" test_contract_determinism
    run_test "negative_contract_failures" test_negative_contract_failures

    print_summary
    if [[ $FAIL_COUNT -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
