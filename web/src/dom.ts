/**
 * The page's only way of making elements. Text goes in through textContent and attributes
 * through setAttribute, so nothing taken from a receipt is ever parsed as markup.
 */

export type Child = Node | string | null | undefined | false;

export interface Props {
  readonly class?: string;
  readonly text?: string;
  readonly attrs?: Readonly<Record<string, string>>;
}

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...children: readonly Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props.class !== undefined) el.className = props.class;
  if (props.text !== undefined) el.textContent = props.text;
  for (const [name, value] of Object.entries(props.attrs ?? {})) el.setAttribute(name, value);
  for (const child of children) {
    if (child !== null && child !== undefined && child !== false) el.append(child);
  }
  return el;
}

export function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (el === null) throw new Error(`The page is missing #${id}`);
  return el as T;
}

/** A link out of the page, or plain text when there is nowhere safe to point. */
export function link(text: string, href: string | undefined): Node {
  if (href === undefined) return document.createTextNode(text);
  return h("a", { text, attrs: { href, target: "_blank", rel: "noopener noreferrer" } });
}

export function dot(state: "ok" | "bad" | "pending"): HTMLSpanElement {
  return h("span", { class: `dot ${state}`, attrs: { "aria-hidden": "true" } });
}

export const prefersReducedMotion = (): boolean => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
