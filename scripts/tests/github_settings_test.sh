#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -r -- "$test_dir"' EXIT
export TEST_DIR="$test_dir"

gh() {
  case "$1 $2" in
    "auth status") return 0 ;;
    "api users/reviewer") echo 123 ;;
    "api repos/example/infra/collaborators/reviewer/permission") echo read ;;
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
        '[.protection_rules[]'*) echo 5 ;;
        '.deployment_branch_policy.custom_branch_policies // false') echo true ;;
        '.can_admins_bypass == false and '*)
          [[ "${TEST_MISSING_REVIEWER:-false}" == true ]] && echo false || echo true
          ;;
        *) echo '{"name":"dev"}' ;;
      esac
      ;;
    "api repos/example/infra/environments/dev/deployment-branch-policies?per_page=100")
      case "$5" in
        *'select(.name != "main"'*) return 0 ;;
        *) echo 456 ;;
      esac
      ;;
    "api repos/example/infra/environments/dev/deployment-branch-policies")
      [[ "${TEST_BAD_BRANCH_POLICY:-false}" == true ]] && echo false || echo true
      ;;
    "api --method")
      if [[ "$3" == POST ]]; then
        echo branch-policy >> "$TEST_DIR/writes"
        cat > "$TEST_DIR/branch-policy"
      else
        echo environment >> "$TEST_DIR/writes"
        cat > "$TEST_DIR/payload"
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
  local mode=${2:-gated}
  {
    printf '%s\n' "$mode"
    [[ "$mode" != gated ]] || printf '%s\n' reviewer
    printf '%s\n' "$1"
  } | bash "$script_dir/00_setup_github_settings.sh" > "$TEST_DIR/output" 2>&1
}
assert_no_secret_output() {
  if grep -q MOCK_SECRET_MUST_NOT_BE_PRINTED "$TEST_DIR/output"; then
    echo "Secret was printed" >&2
    exit 1
  fi
}

run_script n
[[ ! -e "$TEST_DIR/writes" ]]
grep -q 'Cancelled' "$TEST_DIR/output"

run_script y
grep -q 'Setup complete' "$TEST_DIR/output"
grep -q '^secret$' "$TEST_DIR/writes"
grep -q '"id":123' "$TEST_DIR/payload"
grep -q '"can_admins_bypass":false' "$TEST_DIR/payload"
grep -q '"prevent_self_review":true' "$TEST_DIR/payload"
grep -q '"protected_branches":false,"custom_branch_policies":true' "$TEST_DIR/payload"
grep -q '"name":"main","type":"branch"' "$TEST_DIR/branch-policy"
[[ $(cat "$TEST_DIR/DEV_PROTECTION_TIER") == gated ]]
assert_no_secret_output

rm "$TEST_DIR/writes"
export TEST_SECRET_EXISTS=true TEST_EXISTING_ENV=true
run_script y
! grep -q '^secret$' "$TEST_DIR/writes"
grep -q '"wait_timer":5' "$TEST_DIR/payload"
grep -q '"prevent_self_review":true' "$TEST_DIR/payload"
grep -q '"protected_branches":false,"custom_branch_policies":true' "$TEST_DIR/payload"
! grep -q '^branch-policy$' "$TEST_DIR/writes"

rm "$TEST_DIR/writes"
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
export TEST_BAD_BRANCH_POLICY=true
if run_script y; then echo "Incorrect branch policy reported success" >&2; exit 1; fi
! grep -q '^variable ' "$TEST_DIR/writes"
unset TEST_BAD_BRANCH_POLICY

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
printf '\ngated\nreviewer\ny\n' | bash "$script_dir/00_setup_github_settings.sh" > "$TEST_DIR/output" 2>&1
[[ $(cat "$TEST_DIR/SSO_ADMIN_ROLE_ARN") == "$TEST_EXISTING_SSO" ]]
rm "$TEST_DIR/writes"
unset TEST_EXISTING_SSO
printf '\ngated\nreviewer\ny\n' | bash "$script_dir/00_setup_github_settings.sh" > "$TEST_DIR/output" 2>&1
! grep -q '^variable SSO_ADMIN_ROLE_ARN$' "$TEST_DIR/writes"
assert_no_secret_output

rm "$TEST_DIR/writes"
export SSO_ADMIN_ROLE_ARN=arn:aws:iam::123456789012:role/admin
run_script n manual
[[ ! -e "$TEST_DIR/writes" ]]
grep -q 'Cancelled' "$TEST_DIR/output"
run_script y manual
grep -q 'Setup complete' "$TEST_DIR/output"
[[ $(cat "$TEST_DIR/DEV_PROTECTION_TIER") == manual ]]
! grep -Eq '^(environment|branch-policy)$' "$TEST_DIR/writes"
grep -q 'Manual mode does not configure or verify independent deployment approval' "$TEST_DIR/output"
assert_no_secret_output
echo "GitHub settings tests passed (manual/gated modes, cancellation, creation, rerun, preservation, and failure paths)."
