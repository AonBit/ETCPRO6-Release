// Run only after the reviewed public main branch and its CI check exist.
import { spawnSync } from 'node:child_process';
const repository = 'AonBit/ETCPRO6-Release';
function api(route, method = 'GET', body) {
  const args = ['api', route, '--method', method];
  if (body !== undefined) args.push('--input', '-');
  const result = spawnSync('gh', args, { encoding: 'utf8', input: body === undefined ? undefined : JSON.stringify(body), maxBuffer: 1024 ** 2 });
  if (result.error || result.status !== 0) throw new Error('Repository bootstrap API failed; inspect GitHub settings before retry');
  return result.stdout ? JSON.parse(result.stdout) : null;
}
try {
  const repo = api(`repos/${repository}`);
  if (repo.full_name !== repository || repo.private !== false || repo.default_branch !== 'main') throw new Error('Unexpected public repository identity');
  const operator = api('users/clementatt');
  if (operator.login !== 'clementatt' || !Number.isSafeInteger(operator.id)) throw new Error('Unexpected operator identity');
  const checks = api(`repos/${repository}/commits/main/check-runs`);
  const check = checks.check_runs?.find(item => item.name === 'check' && item.app?.slug === 'github-actions' && item.conclusion === 'success');
  if (!Number.isSafeInteger(check?.app?.id)) throw new Error('Successful GitHub Actions check required before bootstrap');
  api(`repos/${repository}/actions/permissions/workflow`, 'PUT', { default_workflow_permissions: 'read', can_approve_pull_request_reviews: false });
  api(`repos/${repository}/branches/main/protection`, 'PUT', {
    required_status_checks: { strict: true, checks: [{ context: 'check', app_id: check.app.id }] }, enforce_admins: true,
    required_pull_request_reviews: null, restrictions: { users: ['clementatt'], teams: [], apps: [] },
    required_linear_history: true, allow_force_pushes: false, allow_deletions: false,
    block_creations: false, required_conversation_resolution: true,
  });
  for (const environment of ['production-candidate', 'production-stable']) {
    api(`repos/${repository}/environments/${environment}`, 'PUT', {
      wait_timer: 0, prevent_self_review: false,
      reviewers: [{ type: 'User', id: operator.id }],
      deployment_branch_policy: { protected_branches: true, custom_branch_policies: false },
      can_admins_bypass: false,
    });
    const actual = api(`repos/${repository}/environments/${environment}`);
    const review = actual.protection_rules?.find(rule => rule.type === 'required_reviewers');
    if (!review?.reviewers?.some(item => item.reviewer?.id === operator.id) || review.prevent_self_review !== false || actual.can_admins_bypass !== false || actual.deployment_branch_policy?.protected_branches !== true) throw new Error('Environment verification failed');
  }
  console.log('Public repository protections configured for the documented single operator. Release enablement and credentials are separate.');
} catch (error) { console.error(error.message); process.exitCode = 1; }
