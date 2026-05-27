# rar

[JSR](https://jsr.io/@mary/rar) | [source code](https://tangled.sh/@mary.my.id/pkg-rar)

streaming RAR extractor

```ts
import { unrar } from '@mary/rar';
import { fromFsFile } from '@mary/rar/deno';

// extracting a specific file from an archive
{
	using file = await Deno.open('./archive.rar');
	const reader = await fromFsFile(file);

	for await (const entry of unrar(reader)) {
		console.log(entry.filename, entry.size);

		if (entry.filename === 'mod.ts') {
			console.log(await entry.text());
		}
	}
}

// password-protected, multi-volume archives — pass the volumes in order
{
	using v1 = await Deno.open('./archive.part1.rar');
	using v2 = await Deno.open('./archive.part2.rar');

	const readers = [await fromFsFile(v1), await fromFsFile(v2)];

	for await (const entry of unrar(readers, { password: 'hunter2' })) {
		console.log(entry.filename, await entry.bytes());
	}
}
```
