import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
afterEach(cleanup);
import { vi } from "vitest";
// next/font is a build-time transform; in tests each face is a plain class name/variable.
vi.mock("next/font/google", () => {
  const face = (name: string) => () => ({
    className: `font-${name}`,
    variable: `font-${name}-variable`,
    style: { fontFamily: name },
  });
  return {
    Chakra_Petch: face("chakra-petch"),
    Inter: face("inter"),
    JetBrains_Mono: face("jetbrains-mono"),
  };
});
