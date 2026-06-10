export const requiredEnv = ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID'];

export function buildApprovalMessage({
  repo,
  refName,
  actor,
  workflow,
  runUrl,
  reason = 'Manual gate check',
}) {
  return [
    'Secret Gate approval requested',
    '',
    `Repo: ${repo}`,
    `Branch: ${refName}`,
    `Workflow: ${workflow}`,
    `Actor: ${actor}`,
    `Reason: ${reason}`,
    '',
    'Approve or reject in GitHub:',
    runUrl,
  ].join('\n');
}
