#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import treeFucker from './tree-fucker.txt' with { type: 'text' };

const outputPath = join(import.meta.dirname, 'tree-fucker.html');
const source = treeFucker.replaceAll('\r\n', '\n');
const lines = source.split('\n');

let bodyStart = 0;
while (bodyStart < lines.length && lines[bodyStart].trim() !== '') bodyStart += 1;

const metadata = Object.fromEntries(
	lines.slice(0, bodyStart).map((line) => {
		const separator = line.indexOf(':');
		if (separator < 1) throw new Error(`Invalid metadata line: ${line}`);
		return [line.slice(0, separator), line.slice(separator + 1).trim()];
	}),
);

for (const field of ['RFC', 'Status', 'Date', 'Author', 'Organization', 'Email', 'URI']) {
	if (!metadata[field]) throw new Error(`Missing RFC metadata: ${field}`);
}

const blocks = [];
for (let index = bodyStart; index < lines.length;) {
	while (index < lines.length && lines[index].trim() === '') index += 1;
	if (index >= lines.length) break;
	const block = [];
	while (index < lines.length && lines[index].trim() !== '') {
		block.push(lines[index]);
		index += 1;
	}
	blocks.push(block);
}

const referenceKeys = new Set();
for (const block of blocks) {
	const match = block[0]?.match(/^\s+\[([A-Z][A-Z0-9-]+)\]/);
	if (match) referenceKeys.add(match[1]);
}

const sectionIds = new Map();

const escapeHtml = (value) =>
	value
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;');

const joinWrapped = (block) =>
	block
		.map((line) => line.trim())
		.reduce((text, line) => {
			if (!text) return line;
			return text.endsWith('-') && /^[a-z]/.test(line)
				? `${text}${line}`
				: `${text} ${line}`;
		}, '');

const formatInline = (input, citations = true) => {
	const tokens = [];
	const stash = (html) => {
		const token = `@@RFC-TOKEN-${tokens.length}@@`;
		tokens.push([token, html]);
		return token;
	};

	let value = input.replace(/`([^`]+)`/g, (_, code) => stash(`<code>${escapeHtml(code)}</code>`));
	value = value.replace(/<(https?:\/\/[^>]+)>/g, (_, url) =>
		stash(
			`<a class="url" href="${escapeHtml(url)}" rel="noreferrer">${escapeHtml(url)}</a>`,
		));
	value = escapeHtml(value);

	value = value.replace(
		/\b(Section|Sections)\s+(\d+(?:\.\d+)?)(?:\s+(and|through|to)\s+(\d+(?:\.\d+)?))?/g,
		(match, label, first, conjunction, second) => {
			const firstId = sectionIds.get(first);
			if (!firstId) return match;
			const firstLink = `<a class="section-reference" href="#${firstId}">${first}</a>`;
			if (!second) return `${label}&nbsp;${firstLink}`;
			const secondId = sectionIds.get(second);
			const secondLink = secondId
				? `<a class="section-reference" href="#${secondId}">${second}</a>`
				: second;
			return `${label}&nbsp;${firstLink} ${conjunction} ${secondLink}`;
		},
	);

	if (citations) {
		value = value.replace(/\[([A-Z][A-Z0-9-]+)\]/g, (match, key) =>
			referenceKeys.has(key)
				? `<a class="citation" href="#ref-${key.toLowerCase()}">${match}</a>`
				: match);
	}

	value = value.replace(
		/\b(MUST NOT|SHALL NOT|SHOULD NOT|NOT RECOMMENDED|MUST|REQUIRED|SHALL|SHOULD|RECOMMENDED|MAY|OPTIONAL)\b/g,
		'<strong class="normative">$1</strong>',
	);

	for (const [token, html] of tokens) value = value.replace(token, html);
	return value;
};

const slugify = (value) =>
	value
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-|-$/g, '');

const headingFor = (block) => {
	if (block.length !== 1 || /^\s/.test(block[0])) return null;
	if (block[0] === 'Abstract') {
		return { depth: 2, id: 'abstract', label: 'Abstract', number: 'A' };
	}
	const subsection = block[0].match(/^(\d+\.\d+)\.\s{2}(.+)$/);
	if (subsection) {
		return {
			depth: 3,
			id: `section-${subsection[1].replaceAll('.', '-')}-${slugify(subsection[2])}`,
			label: subsection[2],
			number: subsection[1],
		};
	}
	const section = block[0].match(/^(\d+)\.\s{2}(.+)$/);
	if (section) {
		return {
			depth: 2,
			id: `section-${section[1]}-${slugify(section[2])}`,
			label: section[2],
			number: section[1],
		};
	}
	return null;
};

for (const block of blocks) {
	const heading = headingFor(block);
	if (heading && heading.number !== 'A') {
		sectionIds.set(heading.number, heading.id);
	}
}

const orderedItemsFor = (block) => {
	const items = [];
	let itemIndent = null;
	let current = null;

	for (const line of block) {
		const match = line.match(/^(\s+)(\d+)\.\s+(.+)$/);
		const indent = match?.[1].length;
		if (match && (itemIndent === null || indent === itemIndent)) {
			if (current) items.push(current);
			itemIndent = indent;
			current = { number: Number(match[2]), lines: [match[3]] };
		} else if (current) {
			current.lines.push(line);
		} else {
			return null;
		}
	}

	if (current) items.push(current);
	return items.length
		? items.map((item) => ({
			number: item.number,
			text: joinWrapped(item.lines),
		}))
		: null;
};

const referenceFor = (block) => {
	const match = block[0]?.match(/^\s+\[([A-Z][A-Z0-9-]+)\]\s*(.*)$/);
	if (!match) return null;
	return {
		key: match[1],
		text: joinWrapped([match[2], ...block.slice(1)]),
	};
};

const definitionFor = (block) => {
	if (block.length < 2) return null;
	const firstIndent = block[0].match(/^\s*/)?.[0].length ?? 0;
	const secondIndent = block[1].match(/^\s*/)?.[0].length ?? 0;
	const term = block[0].trim();
	if (
		firstIndent < 3
		|| secondIndent < firstIndent + 3
		|| term.length > 64
		|| /[=(){};]/.test(term)
	) {
		return null;
	}
	return { term, description: joinWrapped(block.slice(1)) };
};

const isCodeBlock = (block) => {
	const minimumIndent = Math.min(
		...block
			.filter((line) => line.trim())
			.map((line) => line.match(/^\s*/)[0].length),
	);
	if (minimumIndent < 6) return false;
	const text = block.map((line) => line.trim()).join('\n');
	return (
		/^(pub |impl |fn |target_period =|delay =|clamp\(|revision\(\))/m.test(
			text,
		)
		|| /[{};]/.test(text)
		|| /\s->\s/.test(text)
	);
};

const isSpecList = (block) => block.length > 1 && block.every((line) => /^\s{6}\S/.test(line));

const toc = [];
for (const block of blocks) {
	const heading = headingFor(block);
	if (heading?.depth === 2) toc.push(heading);
}

const rendered = [];
let sectionOpen = false;
for (let index = 0; index < blocks.length; index += 1) {
	const block = blocks[index];
	const heading = headingFor(block);
	if (heading) {
		if (heading.depth === 2) {
			if (sectionOpen) rendered.push('</section>');
			rendered.push(
				`<section class="rfc-section${heading.id === 'abstract' ? ' abstract' : ''}" data-section="${heading.id}">`,
			);
			sectionOpen = true;
		}
		rendered.push(
			`<h${heading.depth} id="${heading.id}"><a href="#${heading.id}"><span class="section-number">${heading.number}</span>${
				escapeHtml(
					heading.label,
				)
			}</a></h${heading.depth}>`,
		);
		continue;
	}

	const reference = referenceFor(block);
	if (reference) {
		rendered.push(
			`<div class="reference" id="ref-${reference.key.toLowerCase()}"><span class="reference-key">[${reference.key}]</span><p>${
				formatInline(
					reference.text,
					false,
				)
			}</p></div>`,
		);
		continue;
	}

	const ordered = orderedItemsFor(block);
	if (ordered) {
		const items = [...ordered];
		while (index + 1 < blocks.length) {
			const next = orderedItemsFor(blocks[index + 1]);
			if (!next) break;
			items.push(...next);
			index += 1;
		}
		rendered.push(`<ol start="${items[0].number}">`);
		for (const item of items) {
			rendered.push(
				`<li value="${item.number}">${formatInline(item.text)}</li>`,
			);
		}
		rendered.push('</ol>');
		continue;
	}

	const definition = definitionFor(block);
	if (definition) {
		const definitions = [definition];
		while (index + 1 < blocks.length) {
			const next = definitionFor(blocks[index + 1]);
			if (!next) break;
			definitions.push(next);
			index += 1;
		}
		rendered.push('<dl class="definitions">');
		for (const item of definitions) {
			rendered.push(
				`<div><dt>${formatInline(item.term)}</dt><dd>${formatInline(item.description)}</dd></div>`,
			);
		}
		rendered.push('</dl>');
		continue;
	}

	if (isCodeBlock(block)) {
		const indentation = Math.min(
			...block
				.filter((line) => line.trim())
				.map((line) => line.match(/^\s*/)[0].length),
		);
		const code = block.map((line) => line.slice(indentation)).join('\n');
		rendered.push(`<pre><code>${escapeHtml(code)}</code></pre>`);
		continue;
	}

	if (isSpecList(block)) {
		rendered.push('<ul class="spec-list">');
		for (const line of block) {
			rendered.push(`<li>${formatInline(line.trim())}</li>`);
		}
		rendered.push('</ul>');
		continue;
	}

	rendered.push(`<p>${formatInline(joinWrapped(block))}</p>`);
}
if (sectionOpen) rendered.push('</section>');

const tocLinks = toc
	.map(
		(item) => `<li><a href="#${item.id}" data-section-link="${item.id}"><span>${item.number}</span>${escapeHtml(item.label)}</a></li>`,
	)
	.join('\n');

const hash = createHash('sha256').update(source).digest('hex');
const profileLabel = metadata.URI.replace(/^https?:\/\//, '');
const html = `<!doctype html>
<!-- Generated by render-tree-fucker.mjs from tree-fucker.txt. -->
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="A technical RFC for a bounded, watcher-independent filesystem tree synchronizer.">
  <meta name="author" content="${escapeHtml(metadata.Author)}">
  <title>${escapeHtml(metadata.RFC)} · RFC</title>
  <link rel="author" href="${escapeHtml(metadata.URI)}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap" rel="stylesheet">
  <style>
    :root {
      --ground: #f1f4f0;
      --paper: #fafbf8;
      --ink: #17221e;
      --muted: #65716c;
      --faint: #8b9691;
      --rule: #cad2cd;
      --soft-rule: #e1e6e2;
      --moss: #286247;
      --moss-soft: #dce9e1;
      --oxide: #9a4b32;
      --code: #e7ece8;
      --shadow: rgb(23 34 30 / 8%);
      color-scheme: light;
      font-synthesis: none;
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --ground: #111714;
        --paper: #171e1a;
        --ink: #e5ebe7;
        --muted: #9ba7a1;
        --faint: #75817b;
        --rule: #35413b;
        --soft-rule: #27312c;
        --moss: #80c49b;
        --moss-soft: #20382b;
        --oxide: #e08a69;
        --code: #202a25;
        --shadow: rgb(0 0 0 / 24%);
        color-scheme: dark;
      }
    }

    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background:
        linear-gradient(90deg, transparent 0 3.5rem, var(--soft-rule) 3.5rem calc(3.5rem + 1px), transparent calc(3.5rem + 1px)),
        var(--ground);
      color: var(--ink);
      font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
      font-size: 16px;
      line-height: 1.65;
    }

    a { color: inherit; }
    a:focus-visible {
      outline: 2px solid var(--oxide);
      outline-offset: 4px;
      border-radius: 2px;
    }
    .skip-link {
      position: fixed;
      z-index: 20;
      top: 0.75rem;
      left: 0.75rem;
      padding: 0.55rem 0.8rem;
      background: var(--ink);
      color: var(--paper);
      transform: translateY(-180%);
    }
    .skip-link:focus { transform: translateY(0); }
    .progress {
      position: fixed;
      z-index: 10;
      inset: 0 auto auto 3.5rem;
      width: 2px;
      height: 100vh;
      pointer-events: none;
    }
    .progress::before {
      content: "";
      display: block;
      width: 100%;
      height: 100%;
      background: var(--oxide);
      transform: scaleY(var(--progress, 0));
      transform-origin: top;
    }
    .layout {
      display: grid;
      grid-template-columns: 14rem minmax(0, 52rem);
      gap: clamp(2.5rem, 6vw, 6rem);
      width: min(100% - 4rem, 78rem);
      margin: 0 auto;
      padding: 4rem 0 7rem;
    }
    .rail {
      position: sticky;
      top: 2rem;
      align-self: start;
      max-height: calc(100vh - 4rem);
      overflow: auto;
      scrollbar-width: thin;
    }
    .rail-label,
    .eyebrow,
    .meta,
    .section-number,
    .reference-key {
      font-family: "IBM Plex Mono", ui-monospace, monospace;
    }
    .rail-label {
      margin: 0 0 0.8rem;
      color: var(--faint);
      font-size: 0.67rem;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    .rail ol {
      margin: 0;
      padding: 0 0 0 1rem;
      border-left: 1px solid var(--rule);
      list-style: none;
    }
    .rail li { margin: 0; }
    .rail a {
      position: relative;
      display: grid;
      grid-template-columns: 1.8rem 1fr;
      gap: 0.35rem;
      padding: 0.28rem 0;
      color: var(--muted);
      font-size: 0.76rem;
      line-height: 1.25;
      text-decoration: none;
      transition: color 140ms ease;
    }
    .rail a::before {
      content: "";
      position: absolute;
      top: 0.65rem;
      left: calc(-1rem - 4px);
      width: 7px;
      height: 7px;
      border: 1px solid var(--ground);
      border-radius: 50%;
      background: transparent;
      transform: scale(0.5);
      transition: background 140ms ease, transform 140ms ease;
    }
    .rail a span { color: var(--faint); }
    .rail a:hover,
    .rail a[aria-current="true"] { color: var(--ink); }
    .rail a[aria-current="true"]::before {
      background: var(--oxide);
      transform: scale(1);
    }
    .document { min-width: 0; }
    .hero {
      position: relative;
      padding: clamp(2rem, 5vw, 4rem);
      overflow: hidden;
      border: 1px solid var(--rule);
      background: var(--paper);
      box-shadow: 0 1.2rem 3rem var(--shadow);
    }
    .hero::after {
      content: "";
      position: absolute;
      top: 0;
      right: 0;
      width: 5rem;
      height: 5rem;
      background: linear-gradient(135deg, transparent 49.5%, var(--oxide) 50%);
      opacity: 0.9;
    }
    .eyebrow {
      margin: 0 0 1.15rem;
      color: var(--moss);
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    h1 {
      max-width: 12ch;
      margin: 0;
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: clamp(2.35rem, 7vw, 5.25rem);
      font-weight: 500;
      letter-spacing: -0.075em;
      line-height: 0.93;
      overflow-wrap: anywhere;
    }
    .dek {
      max-width: 36rem;
      margin: 1.7rem 0 2rem;
      color: var(--muted);
      font-size: clamp(1.05rem, 2vw, 1.3rem);
      line-height: 1.45;
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.65rem 1.25rem;
      align-items: center;
      color: var(--muted);
      font-size: 0.74rem;
    }
    .authorship {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.8rem 2rem;
      margin: 1.35rem 0 0;
      padding: 1.15rem 0 0;
      border-top: 1px solid var(--soft-rule);
    }
    .authorship > div { min-width: 0; }
    .authorship dt {
      margin-bottom: 0.15rem;
      color: var(--faint);
      font-size: 0.64rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .authorship dd {
      color: var(--ink);
      font-size: 0.84rem;
      overflow-wrap: anywhere;
    }
    .authorship a { text-underline-offset: 0.18em; }
    .status {
      padding: 0.18rem 0.45rem;
      border: 1px solid var(--moss);
      color: var(--moss);
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .source-link {
      color: var(--ink);
      text-underline-offset: 0.2em;
    }
    .mobile-toc { display: none; }
    article { padding: 1rem clamp(0rem, 3vw, 2rem) 0; }
    .rfc-section {
      padding: 2.7rem 0 0.35rem;
      border-top: 1px solid var(--rule);
      scroll-margin-top: 1rem;
    }
    .rfc-section:first-child { border-top: 0; }
    .rfc-section.abstract {
      margin: 2rem 0 1rem;
      padding: 2rem;
      border: 0;
      background: var(--moss-soft);
    }
    h2,
    h3 {
      margin: 0;
      font-weight: 600;
      line-height: 1.2;
      text-wrap: balance;
    }
    h2 { font-size: clamp(1.45rem, 3vw, 2rem); }
    h3 {
      margin-top: 2rem;
      font-size: 1.05rem;
    }
    h2 a,
    h3 a {
      display: grid;
      grid-template-columns: 2.8rem minmax(0, 1fr);
      gap: 0.6rem;
      align-items: baseline;
      text-decoration: none;
    }
    h3 a { grid-template-columns: 3.4rem minmax(0, 1fr); }
    .section-number {
      color: var(--oxide);
      font-size: 0.65em;
      font-weight: 500;
      letter-spacing: 0;
    }
    article p { margin: 1rem 0; }
    article ol,
    article ul {
      margin: 1rem 0 1.25rem;
      padding-left: 1.35rem;
    }
    article li { margin: 0.5rem 0; padding-left: 0.25rem; }
    article li::marker {
      color: var(--oxide);
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: 0.82em;
      font-weight: 600;
    }
    .spec-list {
      columns: 2 15rem;
      gap: 2rem;
      padding: 1.1rem 1.2rem 1.1rem 2.5rem;
      border: 1px solid var(--soft-rule);
      background: var(--paper);
    }
    .spec-list li { break-inside: avoid; }
    code,
    pre,
    .normative {
      font-family: "IBM Plex Mono", ui-monospace, monospace;
    }
    code {
      padding: 0.08em 0.28em;
      border-radius: 2px;
      background: var(--code);
      font-size: 0.86em;
    }
    pre {
      margin: 1.25rem 0;
      padding: 1rem 1.2rem;
      overflow-x: auto;
      border-left: 3px solid var(--moss);
      background: var(--code);
      font-size: 0.79rem;
      line-height: 1.55;
      tab-size: 4;
    }
    pre code { padding: 0; background: transparent; font-size: inherit; }
    .normative {
      color: var(--moss);
      font-size: 0.88em;
      font-weight: 600;
      letter-spacing: 0.015em;
    }
    .definitions {
      display: grid;
      gap: 0;
      margin: 1.2rem 0;
      border-top: 1px solid var(--soft-rule);
    }
    .definitions > div {
      display: grid;
      grid-template-columns: minmax(8rem, 0.34fr) 1fr;
      gap: 1.25rem;
      padding: 0.9rem 0;
      border-bottom: 1px solid var(--soft-rule);
    }
    dt {
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: 0.82rem;
      font-weight: 600;
    }
    dd { margin: 0; color: var(--muted); }
    .citation {
      color: var(--moss);
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: 0.8em;
      font-weight: 600;
      text-decoration-thickness: 1px;
      text-underline-offset: 0.18em;
    }
    .section-reference {
      color: inherit;
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: 0.86em;
      font-weight: 500;
      text-decoration-color: var(--oxide);
      text-underline-offset: 0.18em;
    }
    .reference {
      display: grid;
      grid-template-columns: 8rem minmax(0, 1fr);
      gap: 1rem;
      padding: 0.85rem 0;
      border-bottom: 1px solid var(--soft-rule);
      scroll-margin-top: 1rem;
    }
    .reference:target {
      margin-inline: -0.8rem;
      padding-inline: 0.8rem;
      background: var(--moss-soft);
    }
    .reference-key {
      color: var(--oxide);
      font-size: 0.75rem;
      font-weight: 600;
    }
    .reference p { margin: 0; }
    .url { overflow-wrap: anywhere; text-underline-offset: 0.18em; }
    .document-footer {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin-top: 4rem;
      padding: 1.2rem 0;
      border-top: 1px solid var(--rule);
      color: var(--muted);
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: 0.72rem;
    }

    @media (max-width: 900px) {
      body { background: var(--ground); }
      .progress { left: 0; }
      .layout {
        display: block;
        width: min(100% - 2rem, 54rem);
        padding-top: 1rem;
      }
      .rail { display: none; }
      .mobile-toc {
        display: block;
        margin: 1rem 0 0;
        border: 1px solid var(--rule);
        background: var(--paper);
      }
      .mobile-toc summary {
        padding: 0.75rem 1rem;
        cursor: pointer;
        font-family: "IBM Plex Mono", ui-monospace, monospace;
        font-size: 0.78rem;
        font-weight: 600;
      }
      .mobile-toc ol {
        columns: 2 12rem;
        margin: 0;
        padding: 0 1rem 1rem 2.5rem;
      }
      .mobile-toc li { break-inside: avoid; margin: 0.25rem 0; }
      .mobile-toc a { font-size: 0.82rem; }
      article { padding-inline: 0; }
    }

    @media (max-width: 560px) {
      .layout { width: min(100% - 1.25rem, 54rem); }
      .hero { padding: 1.5rem; }
      .hero::after { width: 3rem; height: 3rem; }
      h1 { font-size: clamp(2rem, 13vw, 3.25rem); }
      .rfc-section.abstract { margin-top: 1rem; padding: 1.25rem; }
      h2 a,
      h3 a { display: block; }
      .section-number { display: block; margin-bottom: 0.3rem; }
      .definitions > div,
      .reference { grid-template-columns: 1fr; gap: 0.35rem; }
      .authorship { grid-template-columns: 1fr; }
      .spec-list { columns: 1; }
      .mobile-toc ol { columns: 1; }
      .document-footer { display: block; }
    }

    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      *, *::before, *::after { transition: none !important; }
    }

    @media print {
      body { background: white; color: black; font-size: 10pt; }
      .rail, .mobile-toc, .progress, .skip-link { display: none; }
      .layout { display: block; width: auto; padding: 0; }
      .hero { padding: 0 0 2rem; border: 0; box-shadow: none; }
      .hero::after { display: none; }
      article { padding: 0; }
      .rfc-section { break-before: auto; }
      a { text-decoration: none; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#document">Skip to RFC</a>
  <div class="progress" aria-hidden="true"></div>
  <div class="layout">
    <nav class="rail" aria-label="RFC sections">
      <p class="rail-label">Baseline cursor</p>
      <ol>${tocLinks}</ol>
    </nav>
    <main class="document" id="document">
      <header class="hero">
        <p class="eyebrow">Technical RFC · Filesystem synchronization</p>
        <h1>${escapeHtml(metadata.RFC)}</h1>
        <p class="dek">Watcher events reduce latency. Reconciliation establishes truth.</p>
        <div class="meta">
          <span class="status">${escapeHtml(metadata.Status)}</span>
          <time datetime="${escapeHtml(metadata.Date)}">${escapeHtml(metadata.Date)}</time>
          <a class="source-link" href="tree-fucker.txt">Plain-text RFC</a>
        </div>
        <dl class="authorship">
          <div><dt>Author</dt><dd><a href="${escapeHtml(metadata.URI)}" rel="author">${escapeHtml(metadata.Author)}</a></dd></div>
          <div><dt>Organization</dt><dd>${escapeHtml(metadata.Organization)}</dd></div>
          <div><dt>Email</dt><dd><a href="mailto:${escapeHtml(metadata.Email)}">${escapeHtml(metadata.Email)}</a></dd></div>
          <div><dt>Profile</dt><dd><a href="${escapeHtml(metadata.URI)}" rel="author">${escapeHtml(profileLabel)}</a></dd></div>
        </dl>
      </header>
      <details class="mobile-toc">
        <summary>RFC sections</summary>
        <ol>${tocLinks}</ol>
      </details>
      <article data-source-sha256="${hash}">
        ${rendered.join('\n')}
      </article>
      <footer class="document-footer">
        <span>${escapeHtml(metadata.RFC)} · ${escapeHtml(metadata.Author)} · ${escapeHtml(metadata.Status)}</span>
        <a href="#document">Return to top</a>
      </footer>
    </main>
  </div>
  <script>
    const progress = document.querySelector(".progress");
    const links = [...document.querySelectorAll("[data-section-link]")];
    const sections = [...document.querySelectorAll("[data-section]")];

    const setActive = (id) => {
      for (const link of links) {
        if (link.dataset.sectionLink === id) link.setAttribute("aria-current", "true");
        else link.removeAttribute("aria-current");
      }
    };

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.dataset.section);
      },
      { rootMargin: "-12% 0px -75% 0px" },
    );
    for (const section of sections) observer.observe(section);

    const updateProgress = () => {
      const distance = document.documentElement.scrollHeight - window.innerHeight;
      const ratio = distance > 0 ? Math.min(1, window.scrollY / distance) : 1;
      progress.style.setProperty("--progress", ratio);
    };
    updateProgress();
    window.addEventListener("scroll", updateProgress, { passive: true });

    for (const link of document.querySelectorAll(".mobile-toc a")) {
      link.addEventListener("click", () => link.closest("details").removeAttribute("open"));
    }
  </script>
</body>
</html>
`;

writeFileSync(outputPath, html);
execFileSync('dprint', ['fmt', outputPath], { stdio: 'inherit' });
