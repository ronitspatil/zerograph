import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BarList, Donut, RingGauge } from "@/components/charts";

const parts = (value: number) => [
  { key: "a", label: "restricted", value, color: "red" },
];

describe("overview charts", () => {
  it("gives the ring gauge a text equivalent and no Tailwind ring class", () => {
    const { getByRole, container } = render(
      <RingGauge value={0.5} label="Identity EPI" center="50%" caption="x" />,
    );
    expect(getByRole("img").getAttribute("aria-label")).toBe(
      "Identity EPI: 50% x",
    );
    expect(container.querySelector(".ring")).toBeNull();
    expect(container.querySelectorAll(".ring-value")).toHaveLength(1);
  });

  it("draws no arc for an unavailable value", () => {
    const { container } = render(
      <RingGauge value={null} label="Coverage" center="—" />,
    );
    expect(container.querySelectorAll(".ring-value")).toHaveLength(0);
  });

  it("lists every donut segment in its label", () => {
    const { getByRole } = render(
      <Donut
        label="Proposals"
        center="3"
        segments={[
          { key: "h", label: "High", value: 2, color: "green" },
          { key: "l", label: "Low", value: 1, color: "amber" },
        ]}
      />,
    );
    expect(getByRole("img").getAttribute("aria-label")).toContain(
      "High 2, Low 1",
    );
  });

  it("keeps a fixed number of rows while loading, empty and loaded", () => {
    const rows = (node: HTMLElement) =>
      node.querySelectorAll(".bar-row").length;
    const loading = render(<BarList items={[]} rows={6} label="x" loading />);
    expect(rows(loading.container)).toBe(6);
    const empty = render(
      <BarList items={[]} rows={6} label="x" empty="Nothing" />,
    );
    expect(rows(empty.container)).toBe(6);
    expect(empty.container.textContent).toContain("Nothing");
    const items = Array.from({ length: 9 }, (_, i) => ({
      key: String(i),
      label: `topic-${i}`,
      parts: parts(i + 1),
    }));
    const loaded = render(<BarList items={items} rows={6} label="x" />);
    expect(rows(loaded.container)).toBe(6);
    expect(loaded.getAllByRole("listitem")[0].getAttribute("aria-label")).toBe(
      "topic-0: 1",
    );
  });
});
