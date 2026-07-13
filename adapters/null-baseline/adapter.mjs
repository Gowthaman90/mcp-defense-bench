/**
 * Null baseline — a defender with zero protection. The scientific control.
 * It catches nothing, which confirms the fixtures fire and anchors the 0% end of the scale.
 */
export const meta = { tool: "null-baseline", class: "none", reproducible: true };

// eslint-disable-next-line no-unused-vars
export async function assess(_input, _testcase) {
  return { detect: false, enforce: false, signal: "no protection" };
}
