#!/usr/bin/env bun

const abs = (specifier: string): string => Bun.fileURLToPath(import.meta.resolve(specifier));

const siteDir = abs('./_site/');

const assets: Array<[source: string, target: string]> = [
	['./tree-fucker.html', 'index.html'],
	['./tree-fucker.css', 'tree-fucker.css'],
	['./tree-fucker.txt', 'tree-fucker.txt'],
	['./favicon.svg', 'favicon.svg'],
	['./favicon.ico', 'favicon.ico'],
	['./apple-touch-icon.png', 'apple-touch-icon.png'],
];

await Bun.$`rm -rf ${siteDir}`;

for (const [specifier, target] of assets) {
	const file = Bun.file(abs(specifier));
	if (!(await file.exists())) throw new Error(`Missing site asset: ${specifier}`);
	await Bun.write(`${siteDir}${target}`, file);
}

await Bun.write(`${siteDir}.nojekyll`, '');

console.log(`${assets.length} assets written to ${siteDir}`);
