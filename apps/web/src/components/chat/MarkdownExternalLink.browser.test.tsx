import { expect, it } from "vite-plus/test";

import { render } from "../../../test/render";
import "../../index.css";

import { MarkdownExternalLinkContent } from "./MarkdownExternalLink";

it.each(["plain", "formatted"] as const)(
  "keeps %s long links bounded in the DOM without losing text or wrapping",
  async (kind) => {
    const link = (url: string) => (
      <div className="chat-markdown w-64">
        <p>
          <a href={url}>
            <MarkdownExternalLinkContent
              host="github.com"
              plainText={kind === "plain" ? url : null}
            >
              {url}
              {kind === "formatted" ? <strong> details</strong> : null}
            </MarkdownExternalLinkContent>
          </a>
        </p>
      </div>
    );
    const url = (length: number) => `https://github.com/search?q=${"a".repeat(length)}`;
    await using screen = await render(link(url(128)));
    const initialElementCount = screen.container.querySelectorAll("a *").length;

    const longUrl = url(16_000);
    await screen.rerender(link(longUrl));
    const anchor = screen.container.querySelector("a")!;
    const paragraph = screen.container.querySelector("p")!;
    expect(anchor.getAttribute("href")).toBe(longUrl);
    expect(anchor.textContent).toBe(longUrl + (kind === "formatted" ? " details" : ""));
    expect(anchor.querySelectorAll("*")).toHaveLength(initialElementCount);
    expect(paragraph.scrollWidth).toBeLessThanOrEqual(
      screen.container.firstElementChild!.clientWidth,
    );
  },
);
