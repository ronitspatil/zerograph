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
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByText(/identity provider \(OIDC\)/)).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
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

  it("hides SSO when it is not configured and makes the demo the main action", () => {
    render(<Login demo sso={false} />);
    expect(
      screen.queryByRole("link", { name: "Sign in with your organization" }),
    ).not.toBeInTheDocument();
    const demo = screen.getByRole("button", {
      name: "Explore the demo workspace",
    });
    expect(demo).toHaveClass("button-primary");
    expect(screen.queryByText(/isn.t configured/)).not.toBeInTheDocument();
  });

  it("tells a real deployment without OIDC settings to ask an administrator", () => {
    render(<Login demo={false} sso={false} />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Single sign-on isn\u2019t configured — ask your administrator.",
    );
  });
});
