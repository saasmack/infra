#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -r -- "$test_dir"' EXIT
export TEST_DIR="$test_dir"

gh() {
  if [[ "${TEST_FORBID_ENV:-false}" == true && "$*" == *'/environments'* ]]; then
    echo "Manual mode must not access environment settings" >&2
    return 1
  fi
  case "$1 $2" in
    "auth status") return 0 ;;
    "api user")
      [[ "$4" == .id ]] && echo 123 || echo reviewer
      ;;
    "api users/approver") echo 456 ;;
    "api repos/example/infra/collaborators/approver/permission") echo "${TEST_REVIEWER_ACCESS:-read}" ;;
    "api repos/example/infra")
      [[ "$4" == .permissions.admin ]] && echo true || echo 222
      ;;
    "api orgs/example") echo 111 ;;
    "api repos/example/backend"|"api repos/example/frontend"|"api repos/example/gitops") echo 222 ;;
    "api repos/example/infra/actions/variables?per_page=100") echo "${TEST_EXISTING_SSO:-}" ;;
    "api repos/example/infra/environments?per_page=100")
      [[ "${TEST_EXISTING_ENV:-false}" != true ]] || echo dev
      return 0
      ;;
    "api repos/example/infra/environments/dev")
      case "$4" in
        *'.reviewer.id !='*)
          [[ "${TEST_OTHER_REVIEWERS:-false}" != true ]] || echo 999
          return 0
          ;;
        '[.protection_rules'*) echo 5 ;;
        '.deployment_branch_policy.custom_branch_policies // false') echo true ;;
        '.can_admins_bypass == false'*)
          [[ "${TEST_MISSING_REVIEWER:-false}" == true ]] && echo false || echo true
          ;;
        '.can_admins_bypass') echo false ;;
        *) echo '{"name":"dev"}' ;;
      esac
      ;;
    "api repos/example/infra/environments/dev/deployment-branch-policies?per_page=100")
      if [[ "$*" == *'.name !='* ]]; then
        [[ "${TEST_OTHER_BRANCHES:-false}" != true ]] || echo 999
      else
        echo 42
      fi
      return 0
      ;;
    "api repos/example/infra/environments/dev/deployment-branch-policies")
      [[ "${TEST_BAD_BRANCH_READBACK:-false}" == true ]] && echo false || echo true
      ;;
    "api --method")
      echo environment >> "$TEST_DIR/writes"
      if [[ "$3" == PUT ]]; then
        cat > "$TEST_DIR/payload"
      else
        cat > "$TEST_DIR/branch-payload"
      fi
      [[ "${TEST_UNSUPPORTED:-false}" != true ]]
      ;;
    "variable set")
      echo "variable $3" >> "$TEST_DIR/writes"
      printf '%s' "$7" > "$TEST_DIR/$3"
      ;;
    "secret set")
      echo secret >> "$TEST_DIR/writes"
      cat >/dev/null
      ;;
    "secret list")
      if [[ "$*" == *'any(.[]'* ]]; then
        echo true
      elif [[ "$*" == *'--json'* ]]; then
        [[ "${TEST_SECRET_EXISTS:-false}" != true ]] || echo DEV_JWT_SECRET
        return 0
      else
        echo DEV_JWT_SECRET
      fi
      ;;
    "variable list") echo "GH_ORG example" ;;
    "api repos/example/infra/actions/variables/"*)
      if [[ "${TEST_BAD_READBACK:-false}" == true ]]; then
        echo unexpected-value
      else
        cat "$TEST_DIR/${2##*/}"
      fi
      ;;
    *) echo "Unexpected gh command: $*" >&2; return 1 ;;
  esac
}
terraform() {
  [[ "${TEST_TERRAFORM_FAILURE:-false}" != true ]] || return 1
  case "${*: -1}" in
    terraform_plan_role_arn) echo arn:aws:iam::123456789012:role/plan ;;
    terraform_apply_role_arn) echo arn:aws:iam::123456789012:role/apply ;;
    *) return 1 ;;
  esac
}
openssl() { echo MOCK_SECRET_MUST_NOT_BE_PRINTED; }
export -f gh terraform openssl
export GITHUB_ORG=example STATE_BUCKET=example-state-bucket
export SSO_ADMIN_ROLE_ARN=arn:aws:iam::123456789012:role/admin

run_script() {
  if [[ "${TEST_MODE:-gated}" == gated ]]; then
    printf 'gated\napprover\n%s\n' "$1"
  else
    printf '%s\n%s\n' "$TEST_MODE" "$1"
  fi | bash "$script_dir/00_setup_github_settings.sh" > "$TEST_DIR/output" 2>&1
}
assert_no_secret_output() {
  if grep -q MOCK_SECRET_MUST_NOT_BE_PRINTED "$TEST_DIR/output"; then
    echo "Secret was printed" >&2
    exit 1
  fi
}

export TEST_MODE=invalid
if run_script y; then echo "Invalid mode accepted" >&2; exit 1; fi
[[ ! -e "$TEST_DIR/writes" ]]
for old_mode in free paid; do
  export TEST_MODE=$old_mode
  if run_script y; then echo "Legacy mode accepted: $old_mode" >&2; exit 1; fi
  [[ ! -e "$TEST_DIR/writes" ]]
done
if bash "$script_dir/00_setup_github_settings.sh" </dev/null > "$TEST_DIR/output" 2>&1; then
  echo "Missing mode accepted" >&2; exit 1
fi
[[ ! -e "$TEST_DIR/writes" ]]
export TEST_MODE=manual TEST_FORBID_ENV=true
run_script n
[[ ! -e "$TEST_DIR/writes" ]]
run_script y
grep -q 'Setup complete' "$TEST_DIR/output"
grep -q 'does not configure or verify independent deployment approval' "$TEST_DIR/output"
! grep -q '^environment$' "$TEST_DIR/writes"
[[ $(cat "$TEST_DIR/DEV_PROTECTION_TIER") == manual ]]
grep -q '^secret$' "$TEST_DIR/writes"
assert_no_secret_output
rm "$TEST_DIR/writes"
unset TEST_MODE TEST_FORBID_ENV

export TEST_REVIEWER_ACCESS=none
if run_script y; then echo "Reviewer without read access accepted" >&2; exit 1; fi
[[ ! -e "$TEST_DIR/writes" ]]
unset TEST_REVIEWER_ACCESS

run_script n
[[ ! -e "$TEST_DIR/writes" ]]
grep -q 'Cancelled' "$TEST_DIR/output"

run_script y
grep -q 'Setup complete' "$TEST_DIR/output"
grep -q '^secret$' "$TEST_DIR/writes"
grep -q '"id":456' "$TEST_DIR/payload"
grep -q '"prevent_self_review":true' "$TEST_DIR/payload"
grep -q '"can_admins_bypass":false' "$TEST_DIR/payload"
grep -q '"custom_branch_policies":true' "$TEST_DIR/payload"
grep -q '"name":"main","type":"branch"' "$TEST_DIR/branch-payload"
[[ $(cat "$TEST_DIR/DEV_PROTECTION_TIER") == gated ]]
assert_no_secret_output

rm "$TEST_DIR/writes"
export TEST_SECRET_EXISTS=true TEST_EXISTING_ENV=true
run_script y
! grep -q '^secret$' "$TEST_DIR/writes"
grep -q '"wait_timer":5' "$TEST_DIR/payload"
grep -q '"prevent_self_review":true' "$TEST_DIR/payload"
grep -q '"protected_branches":false' "$TEST_DIR/payload"

rm "$TEST_DIR/writes"
export TEST_OTHER_BRANCHES=true
if run_script y; then echo "Other deployment branches accepted" >&2; exit 1; fi
[[ ! -e "$TEST_DIR/writes" ]]
unset TEST_OTHER_BRANCHES
export TEST_OTHER_REVIEWERS=true
if run_script y; then echo "Other reviewers were silently removed" >&2; exit 1; fi
[[ ! -e "$TEST_DIR/writes" ]]
unset TEST_OTHER_REVIEWERS TEST_EXISTING_ENV

export TEST_UNSUPPORTED=true
if run_script y; then echo "Unsupported protection reported success" >&2; exit 1; fi
! grep -q '^variable ' "$TEST_DIR/writes"
unset TEST_UNSUPPORTED

rm "$TEST_DIR/writes"
export TEST_MISSING_REVIEWER=true
if run_script y; then echo "Missing reviewer reported success" >&2; exit 1; fi
! grep -q '^variable ' "$TEST_DIR/writes"
unset TEST_MISSING_REVIEWER

rm "$TEST_DIR/writes"
export TEST_BAD_BRANCH_READBACK=true
if run_script y; then echo "Incorrect branch policy reported success" >&2; exit 1; fi
! grep -q '^variable ' "$TEST_DIR/writes"
unset TEST_BAD_BRANCH_READBACK

rm "$TEST_DIR/writes"
export TEST_BAD_READBACK=true
if run_script y; then echo "Incorrect variable readback reported success" >&2; exit 1; fi
grep -q 'Verification failed' "$TEST_DIR/output"
unset TEST_BAD_READBACK

rm "$TEST_DIR/writes"
export TEST_TERRAFORM_FAILURE=true
if run_script y; then echo "Terraform failure reported success" >&2; exit 1; fi
[[ ! -e "$TEST_DIR/writes" ]]
assert_no_secret_output
unset TEST_TERRAFORM_FAILURE SSO_ADMIN_ROLE_ARN
export TEST_EXISTING_SSO=arn:aws:iam::123456789012:role/existing-admin
printf '\ngated\napprover\ny\n' | bash "$script_dir/00_setup_github_settings.sh" > "$TEST_DIR/output" 2>&1
[[ $(cat "$TEST_DIR/SSO_ADMIN_ROLE_ARN") == "$TEST_EXISTING_SSO" ]]
rm "$TEST_DIR/writes"
unset TEST_EXISTING_SSO
printf '\ngated\napprover\ny\n' | bash "$script_dir/00_setup_github_settings.sh" > "$TEST_DIR/output" 2>&1
! grep -q '^variable SSO_ADMIN_ROLE_ARN$' "$TEST_DIR/writes"
assert_no_secret_output

workflow_condition() {
  awk -v job="$2" '
    $0 == "  " job ":" { in_job=1; next }
    in_job && /^  [a-zA-Z_-]+:/ { exit }
    in_job && /^    if: \|/ { in_condition=1; next }
    in_condition && /^      / { print; next }
    in_condition { exit }
  ' "$script_dir/../.github/workflows/$1"
}

check_workflow() {
  local file=$1 job=$2 condition ref mode event action confirmation expected actual
  condition=$(workflow_condition "$file" "$job")
  [[ -n "$condition" ]]
  condition=${condition//github.ref/\$ref}
  condition=${condition//vars.DEV_PROTECTION_TIER/\$mode}
  condition=${condition//github.event_name/\$event}
  condition=${condition//github.event.inputs.confirm_destroy/\$confirmation}
  condition=${condition//github.event.inputs.action/\$action}
  condition=${condition//inputs.action/\$action}
  for ref in refs/heads/main refs/heads/feature refs/tags/main; do
    for mode in manual gated '' invalid free paid; do
      for event in push pull_request workflow_dispatch; do
        for action in plan apply destroy; do
          for confirmation in '' destroy; do
            expected=false
            if [[ "$ref" == refs/heads/main && ( "$mode" == manual || "$mode" == gated ) ]]; then
              if [[ "$job" == destroy ]]; then
                if [[ "$event" == workflow_dispatch && "$action" == destroy && "$confirmation" == destroy ]]; then
                  expected=true
                fi
              elif [[ ( "$event" == push && "$mode" == gated ) || ( "$event" == workflow_dispatch && "$action" == apply ) ]]; then
                expected=true
              fi
            fi
            actual=false
            if eval "[[ $condition ]]"; then actual=true; fi
            if [[ "$actual" != "$expected" ]]; then
              echo "Workflow guard mismatch: $file $job $ref mode=$mode $event $action confirm=$confirmation" >&2
              exit 1
            fi
          done
        done
      done
    done
  done
}
check_workflow bootstrap.yml apply
check_workflow terraform.yml apply
check_workflow terraform.yml destroy
grep -q 'needs: \[plan, security-scan\]' "$script_dir/../.github/workflows/terraform.yml"
grep -q 'needs: security-scan' "$script_dir/../.github/workflows/terraform.yml"
grep -q 'needs: plan' "$script_dir/../.github/workflows/bootstrap.yml"
echo "GitHub settings tests passed (mode selection, protection, preservation, failure paths, and 972 workflow guard cases)."
