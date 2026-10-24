import { fireEvent, render, screen } from "@testing-library/react";
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

  it("keeps organization sign-in visible without OIDC and explains it on click", () => {
    render(<Login demo sso={false} />);
    const demo = screen.getByRole("button", {
      name: "Explore the demo workspace",
    });
    expect(demo).toHaveClass("button-primary");
    expect(
      screen.queryByRole("link", { name: "Sign in with your organization" }),
    ).not.toBeInTheDocument();
    const organization = screen.getByRole("button", {
      name: "Sign in with your organization",
    });
    expect(organization).toHaveClass("button-outline");
    expect(organization).toBeEnabled();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(
      screen.getByText(/works once your administrator configures OIDC/),
    ).toBeInTheDocument();
    fireEvent.click(organization);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Single sign-on isn\u2019t configured \u2014 ask your administrator.",
    );
    expect(screen.queryByText(/works once your administrator/)).toBeNull();
    expect(organization).toHaveAccessibleDescription(
      "Single sign-on isn\u2019t configured \u2014 ask your administrator.",
    );
    expect(demo.compareDocumentPosition(organization)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
  });

  it("keeps the demo primary in demo mode when SSO is configured", () => {
    render(<Login demo sso />);
    expect(
      screen.getByRole("button", { name: "Explore the demo workspace" }),
    ).toHaveClass("button-primary");
    const organization = screen.getByRole("link", {
      name: "Sign in with your organization",
    });
    expect(organization).toHaveAttribute("href", "/api/auth/login");
    expect(organization).toHaveClass("button-outline");
  });

  it("makes organization sign-in the main action when SSO is configured and the demo is off", () => {
    render(<Login demo={false} sso />);
    expect(
      screen.getByRole("link", { name: "Sign in with your organization" }),
    ).toHaveClass("button-primary");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("tells a real deployment without OIDC settings to ask an administrator", () => {
    render(<Login demo={false} sso={false} />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign in with your organization" }),
    ).toHaveClass("button-primary");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Single sign-on isn\u2019t configured \u2014 ask your administrator.",
    );
  });

  it("explains sign-in failures by cause", () => {
    const { unmount } = render(<Login demo sso error="configuration" />);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Single sign-on couldn\u2019t start",
    );
    unmount();
    render(<Login demo sso error="authentication" />);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "may not have access to ZeroGraph",
    );
  });
});
