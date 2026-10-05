import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { LogoMark } from "@/components/ui/logo";

describe("LogoMark", () => {
  it("gives each instance its own gradient id and references it", () => {
    const { container } = render(
      <>
        <LogoMark />
        <LogoMark size={28} />
      </>,
    );
    const gradients = [...container.querySelectorAll("linearGradient")];
    expect(gradients).toHaveLength(2);
    const ids = gradients.map((g) => g.id);
    expect(new Set(ids).size).toBe(2);
    for (const id of ids) {
      expect(id).toMatch(/^[a-zA-Z0-9_-]+$/);
      expect(
        container.querySelector(`path[fill="url(#${id})"]`),
      ).not.toBeNull();
    }
  });
});
