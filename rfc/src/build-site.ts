#!/usr/bin/env bun

import { dirname } from 'path';
import html from './render.ts';

const rfcRoot = `${dirname(import.meta.dir)}/`;
const abs = (specifier: string, fromRoot?: boolean): string => Bun.fileURLToPath(import.meta.resolve(specifier, fromRoot ? rfcRoot : undefined));

const siteDir = abs('./_site/', true);
const staticDir = abs('./static/', true);
const rfcText = abs('./tree-fucker.txt', true);
const dprintConfig = abs('./.dprint.json', true);
const apiSource = abs('../target/doc/', true);
const apiCrate = 'tree_fucker';

await Bun.$`rm -rf ${siteDir}`;
await Bun.$`cp -R ${staticDir} ${siteDir}`;
await Bun.write(`${siteDir}tree-fucker.txt`, Bun.file(rfcText));

await Bun.$`cat < ${new Response(html)} | dprint fmt -c=${dprintConfig} --stdin index.html > ${Bun.file(`${siteDir}index.html`)}`;

await Bun.$`bunx --bun svg-to-ico generate ${siteDir}favicon.svg --out-dir ${siteDir} --quiet`;

if (await Bun.file(`${apiSource}${apiCrate}/index.html`).exists()) {
	await Bun.$`cp -R ${apiSource} ${siteDir}api`;
	await Bun.$`rm -f ${siteDir}api/.lock`;
	await Bun.write(
		`${siteDir}api/index.html`,
		`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=${apiCrate}/"><link rel="canonical" href="${apiCrate}/"><title>tree-fucker API</title><a href="${apiCrate}/">tree-fucker API documentation</a>`,
	);
	console.log(`api docs copied from ${apiSource}`);
} else if (process.env.SITE_REQUIRE_API) {
	throw new Error(`Missing api docs: ${apiSource}${apiCrate}/index.html`);
}

await Bun.write(`${siteDir}.nojekyll`, '');

console.log(`site written to ${siteDir}`);
