#!/usr/bin/env bun
import html from './render-tree-fucker.ts';

const ids = new Map<string, number>();
const targets = new Set<string>();

new HTMLRewriter()
	.on('[id]', {
		element(element) {
			const id = element.getAttribute('id');
			if (id) ids.set(id, (ids.get(id) ?? 0) + 1);
		},
	})
	.on('a[href^="#"]', {
		element(element) {
			const href = element.getAttribute('href');
			if (href && href.length > 1) targets.add(href.slice(1));
		},
	})
	.transform(html);

const missing = [...targets].filter((target) => !ids.has(target)).sort();
const duplicates = [...ids]
	.filter(([, count]) => count > 1)
	.map(([id]) => id)
	.sort();

for (const target of missing) console.error(`unresolved anchor: #${target}`);
for (const id of duplicates) console.error(`duplicate id: ${id}`);

if (missing.length > 0 || duplicates.length > 0) process.exit(1);
console.log(`${targets.size} internal anchors resolve against ${ids.size} ids`);
