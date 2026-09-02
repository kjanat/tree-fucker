#!/usr/bin/env bun

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import treeFucker from './tree-fucker.txt' with { type: 'text' };

type Block = string[];

interface Heading {
	depth: 2 | 3;
	id: string;
	label: string;
	number: string;
}

interface OrderedItem {
	number: number;
	text: string;
}

interface Reference {
	key: string;
	text: string;
}

interface Definition {
	term: string;
	description: string;
}

const METADATA_FIELDS = ['RFC', 'Status', 'Date', 'Author', 'Organization', 'Email', 'URI'] as const;

type MetadataField = (typeof METADATA_FIELDS)[number];
type Metadata = Record<MetadataField, string>;

const outputPath = join(import.meta.dirname, 'tree-fucker.html');
const source = treeFucker.replaceAll('\r\n', '\n');
const lines = source.split('\n');

let bodyStart = 0;
while (bodyStart < lines.length && (lines[bodyStart] ?? '').trim() !== '') bodyStart += 1;

const readMetadata = (header: string[]): Metadata => {
	const fields = new Map<string, string>();
	for (const line of header) {
		const separator = line.indexOf(':');
		if (separator < 1) throw new Error(`Invalid metadata line: ${line}`);
		fields.set(line.slice(0, separator), line.slice(separator + 1).trim());
	}
	const required = (field: MetadataField): string => {
		const value = fields.get(field);
		if (!value) throw new Error(`Missing RFC metadata: ${field}`);
		return value;
	};
	return {
		RFC: required('RFC'),
		Status: required('Status'),
		Date: required('Date'),
		Author: required('Author'),
		Organization: required('Organization'),
		Email: required('Email'),
		URI: required('URI'),
	};
};

const metadata = readMetadata(lines.slice(0, bodyStart));

const blocks: Block[] = [];
for (let index = bodyStart; index < lines.length;) {
	while (index < lines.length && (lines[index] ?? '').trim() === '') index += 1;
	if (index >= lines.length) break;
	const block: Block = [];
	for (; index < lines.length; index += 1) {
		const line = lines[index];
		if (line === undefined || line.trim() === '') break;
		block.push(line);
	}
	blocks.push(block);
}

const referenceKeys = new Set<string>();
for (const block of blocks) {
	const key = block[0]?.match(/^\s+\[([A-Z][A-Z0-9-]+)\]/)?.[1];
	if (key !== undefined) referenceKeys.add(key);
}

const sectionIds = new Map<string, string>();

const escapeHtml = (value: string): string =>
	value
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;');

const indentOf = (line: string): number => /^\s*/.exec(line)?.[0].length ?? 0;

const minimumIndent = (block: Block): number => Math.min(...block.filter((line) => line.trim()).map(indentOf));

const joinWrapped = (block: Block): string =>
	block
		.map((line) => line.trim())
		.reduce((text, line) => {
			if (!text) return line;
			return text.endsWith('-') && /^[a-z]/.test(line) ? `${text}${line}` : `${text} ${line}`;
		}, '');

const formatInline = (input: string, citations = true): string => {
	const tokens: Array<[token: string, html: string]> = [];
	const stash = (html: string): string => {
		const token = `@@RFC-TOKEN-${tokens.length}@@`;
		tokens.push([token, html]);
		return token;
	};

	let value = input.replace(/`([^`]+)`/g, (_: string, code: string) => stash(`<code>${escapeHtml(code)}</code>`));
	value = value.replace(
		/<(https?:\/\/[^>]+)>/g,
		(_: string, url: string) => stash(`<a class="url" href="${escapeHtml(url)}" rel="noreferrer">${escapeHtml(url)}</a>`),
	);
	value = escapeHtml(value);

	value = value.replace(
		/\b(Section|Sections)\s+(\d+(?:\.\d+)?)(?:\s+(and|through|to)\s+(\d+(?:\.\d+)?))?/g,
		(match: string, label: string, first: string, conjunction: string | undefined, second: string | undefined) => {
			const firstId = sectionIds.get(first);
			if (!firstId) return match;
			const firstLink = `<a class="section-reference" href="#${firstId}">${first}</a>`;
			if (second === undefined) return `${label}&nbsp;${firstLink}`;
			const secondId = sectionIds.get(second);
			const secondLink = secondId ? `<a class="section-reference" href="#${secondId}">${second}</a>` : second;
			return `${label}&nbsp;${firstLink} ${conjunction} ${secondLink}`;
		},
	);

	if (citations) {
		value = value.replace(
			/\[([A-Z][A-Z0-9-]+)\]/g,
			(match: string, key: string) => referenceKeys.has(key) ? `<a class="citation" href="#ref-${key.toLowerCase()}">${match}</a>` : match,
		);
	}

	value = value.replace(
		/\b(MUST NOT|SHALL NOT|SHOULD NOT|NOT RECOMMENDED|MUST|REQUIRED|SHALL|SHOULD|RECOMMENDED|MAY|OPTIONAL)\b/g,
		'<strong class="normative">$1</strong>',
	);

	for (const [token, html] of tokens) value = value.replace(token, html);
	return value;
};

const slugify = (value: string): string =>
	value
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-|-$/g, '');

const headingFor = (block: Block): Heading | null => {
	const [only] = block;
	if (block.length !== 1 || only === undefined || /^\s/.test(only)) return null;
	if (only === 'Abstract') {
		return { depth: 2, id: 'abstract', label: 'Abstract', number: 'A' };
	}
	const [, subsectionNumber, subsectionLabel] = only.match(/^(\d+\.\d+)\.\s{2}(.+)$/) ?? [];
	if (subsectionNumber !== undefined && subsectionLabel !== undefined) {
		return {
			depth: 3,
			id: `section-${subsectionNumber.replaceAll('.', '-')}-${slugify(subsectionLabel)}`,
			label: subsectionLabel,
			number: subsectionNumber,
		};
	}
	const [, sectionNumber, sectionLabel] = only.match(/^(\d+)\.\s{2}(.+)$/) ?? [];
	if (sectionNumber !== undefined && sectionLabel !== undefined) {
		return {
			depth: 2,
			id: `section-${sectionNumber}-${slugify(sectionLabel)}`,
			label: sectionLabel,
			number: sectionNumber,
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

const orderedItemsFor = (block: Block): OrderedItem[] | null => {
	const items: Array<{ number: number; lines: string[] }> = [];
	let itemIndent: number | null = null;
	let current: { number: number; lines: string[] } | null = null;

	for (const line of block) {
		const [, indent, number, text] = line.match(/^(\s+)(\d+)\.\s+(.+)$/) ?? [];
		if (indent !== undefined && number !== undefined && text !== undefined && (itemIndent === null || indent.length === itemIndent)) {
			if (current) items.push(current);
			itemIndent = indent.length;
			current = { number: Number(number), lines: [text] };
		} else if (current) {
			current.lines.push(line);
		} else {
			return null;
		}
	}

	if (current) items.push(current);
	return items.length ? items.map((item) => ({ number: item.number, text: joinWrapped(item.lines) })) : null;
};

const referenceFor = (block: Block): Reference | null => {
	const [, key, rest] = block[0]?.match(/^\s+\[([A-Z][A-Z0-9-]+)\]\s*(.*)$/) ?? [];
	if (key === undefined || rest === undefined) return null;
	return { key, text: joinWrapped([rest, ...block.slice(1)]) };
};

const definitionFor = (block: Block): Definition | null => {
	const [first, second] = block;
	if (first === undefined || second === undefined) return null;
	const firstIndent = indentOf(first);
	const secondIndent = indentOf(second);
	const term = first.trim();
	if (firstIndent < 3 || secondIndent < firstIndent + 3 || term.length > 64 || /[=(){};]/.test(term)) {
		return null;
	}
	return { term, description: joinWrapped(block.slice(1)) };
};

const isCodeBlock = (block: Block): boolean => {
	if (minimumIndent(block) < 6) return false;
	const text = block.map((line) => line.trim()).join('\n');
	return /^(pub |impl |fn |target_period =|delay =|clamp\(|revision\(\))/m.test(text) || /[{};]/.test(text) || /\s->\s/.test(text);
};

const isSpecList = (block: Block): boolean => block.length > 1 && block.every((line) => /^\s{6}\S/.test(line));

const toc: Heading[] = [];
for (const block of blocks) {
	const heading = headingFor(block);
	if (heading?.depth === 2) toc.push(heading);
}

const rendered: string[] = [];
let sectionOpen = false;
for (let index = 0; index < blocks.length; index += 1) {
	const block = blocks[index];
	if (block === undefined) break;
	const heading = headingFor(block);
	if (heading) {
		if (heading.depth === 2) {
			if (sectionOpen) rendered.push('</section>');
			rendered.push(`<section class="rfc-section${heading.id === 'abstract' ? ' abstract' : ''}" data-section="${heading.id}">`);
			sectionOpen = true;
		}
		rendered.push(
			`<h${heading.depth} id="${heading.id}"><a href="#${heading.id}"><span class="section-number">${heading.number}</span>${
				escapeHtml(heading.label)
			}</a></h${heading.depth}>`,
		);
		continue;
	}

	const reference = referenceFor(block);
	if (reference) {
		rendered.push(
			`<div class="reference" id="ref-${reference.key.toLowerCase()}"><span class="reference-key">[${reference.key}]</span><p>${
				formatInline(reference.text, false)
			}</p></div>`,
		);
		continue;
	}

	const ordered = orderedItemsFor(block);
	if (ordered) {
		const items = [...ordered];
		while (index + 1 < blocks.length) {
			const following = blocks[index + 1];
			const next = following === undefined ? null : orderedItemsFor(following);
			if (!next) break;
			items.push(...next);
			index += 1;
		}
		rendered.push(`<ol start="${items[0]?.number ?? 1}">`);
		for (const item of items) {
			rendered.push(`<li value="${item.number}">${formatInline(item.text)}</li>`);
		}
		rendered.push('</ol>');
		continue;
	}

	const definition = definitionFor(block);
	if (definition) {
		const definitions = [definition];
		while (index + 1 < blocks.length) {
			const following = blocks[index + 1];
			const next = following === undefined ? null : definitionFor(following);
			if (!next) break;
			definitions.push(next);
			index += 1;
		}
		rendered.push('<dl class="definitions">');
		for (const item of definitions) {
			rendered.push(`<div><dt>${formatInline(item.term)}</dt><dd>${formatInline(item.description)}</dd></div>`);
		}
		rendered.push('</dl>');
		continue;
	}

	if (isCodeBlock(block)) {
		const indentation = minimumIndent(block);
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
	.map((item) => `<li><a href="#${item.id}" data-section-link="${item.id}"><span>${item.number}</span>${escapeHtml(item.label)}</a></li>`)
	.join('\n');

const hash = createHash('sha256').update(source).digest('hex');
const profileLabel = metadata.URI.replace(/^https?:\/\//, '');
const html = `<!doctype html>
<!-- Generated by ${import.meta.file} from tree-fucker.txt. -->
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
  <link rel="stylesheet" href="tree-fucker.css">
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

if (import.meta.main) {
	writeFileSync(outputPath, html);
	execFileSync('dprint', ['fmt', outputPath], { stdio: 'inherit' });
}

export default html;
