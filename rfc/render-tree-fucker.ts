#!/usr/bin/env bun

import { createHash } from 'node:crypto';
import template from './tree-fucker.template.html' with { type: 'text' };
import treeFucker from './tree-fucker.txt' with { type: 'text' };

const abs = (specifier: string): string => Bun.fileURLToPath(import.meta.resolve(specifier));

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

const outputPath = Bun.file(abs('./tree-fucker.html'));
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

const rewriter = new HTMLRewriter();
const filled = new Set<string>();
const fill = (name: string, apply: (element: HTMLRewriterTypes.Element) => void): void => {
	rewriter.on(`[data-fill="${name}"]`, {
		element(element) {
			apply(element);
			element.removeAttribute('data-fill');
			filled.add(name);
		},
	});
};

fill('title', (element) => element.setInnerContent(`${metadata.RFC} · RFC`));
fill('author-name', (element) => element.setAttribute('content', metadata.Author));
fill('author-url', (element) => element.setAttribute('href', metadata.URI));
fill('rfc', (element) => element.setInnerContent(metadata.RFC));
fill('status', (element) => element.setInnerContent(metadata.Status));
fill('date', (element) => element.setAttribute('datetime', metadata.Date).setInnerContent(metadata.Date));
fill('author', (element) => element.setAttribute('href', metadata.URI).setInnerContent(metadata.Author));
fill('organization', (element) => element.setInnerContent(metadata.Organization));
fill('email', (element) => element.setAttribute('href', `mailto:${metadata.Email}`).setInnerContent(metadata.Email));
fill('profile', (element) => element.setAttribute('href', metadata.URI).setInnerContent(profileLabel));
fill('toc', (element) => element.setInnerContent(tocLinks, { html: true }));
fill('article', (element) => element.setAttribute('data-source-sha256', hash).setInnerContent(rendered.join('\n'), { html: true }));
fill('footer', (element) => element.setInnerContent(`${metadata.RFC} · ${metadata.Author} · ${metadata.Status}`));
rewriter.on('html', {
	element(element) {
		element.before(`<!-- Generated by ${import.meta.file} from tree-fucker.template.html. -->\n`, { html: true });
	},
});

const html = rewriter.transform(template);

const placeholders = [
	'title',
	'author-name',
	'author-url',
	'rfc',
	'status',
	'date',
	'author',
	'organization',
	'email',
	'profile',
	'toc',
	'article',
	'footer',
];
const unfilled = placeholders.filter((name) => !filled.has(name));
if (unfilled.length > 0) throw new Error(`Template placeholders missing: ${unfilled.join(', ')}`);

if (import.meta.main) {
	await Bun.$`cat < ${new Response(html)} | bunx dprint fmt -c=../.dprint.jsonc --stdin index.html > ${outputPath}`
		.cwd(import.meta.dir);
}

export default html;
