import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Login } from "@/components/login";

describe("Login", () => {
  it("keeps the sign-in actions and brand, with the mark hidden from assistive tech", () => {
    const { container } = render(<Login demo />);
    expect(
      screen.getByRole("heading", { level: 1, name: "Sign in" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Sign in with your organization" }),
    ).toHaveAttribute("href", "/api/auth/login");
    expect(
      screen.getByRole("button", { name: "Explore the demo workspace" }),
    ).toBeEnabled();
    expect(screen.getByText("ZeroGraph")).toBeInTheDocument();
    for (const svg of container.querySelectorAll("svg"))
      expect(svg).toHaveAttribute("aria-hidden", "true");
  });

  it("omits the demo entry outside demo mode and surfaces sign-in errors", () => {
    render(<Login demo={false} error="callback" />);
    expect(
      screen.queryByRole("button", { name: "Explore the demo workspace" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Sign-in failed");
  });
});
