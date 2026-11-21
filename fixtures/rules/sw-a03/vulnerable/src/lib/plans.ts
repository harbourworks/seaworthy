export const unlimitedPlan = "team";
export const accurateLimit = 4000;

export function wordBudget(plan: string): number {
  return plan === unlimitedPlan ? accurateLimit * 2 : accurateLimit;
}
