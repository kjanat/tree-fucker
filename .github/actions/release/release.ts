import { BunRuntime, BunServices } from '@effect/platform-bun';
import { Config, Console, Effect, FileSystem, Layer, Option, Redacted, Schema, Stream } from 'effect';
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from 'effect/http';
import { ChildProcess, ChildProcessSpawner } from 'effect/process';

const REPOSITORY = 'kjanat/tree-fucker';
const CRATE = 'tree-fucker';
const USER_AGENT = `${CRATE}-release (https://github.com/${REPOSITORY})`;

export class InvalidContext extends Schema.TaggedError<InvalidContext>()('InvalidContext', { message: Schema.String }) {}
export class ReleaseRejected extends Schema.TaggedError<ReleaseRejected>()('ReleaseRejected', { message: Schema.String }) {}
export class InvalidArchive extends Schema.TaggedError<InvalidArchive>()('InvalidArchive', { message: Schema.String }) {}
export class CommandFailed extends Schema.TaggedError<CommandFailed>()('CommandFailed', { message: Schema.String }) {}
export class RequestFailed extends Schema.TaggedError<RequestFailed>()('RequestFailed', { message: Schema.String }) {}

const Sha = Schema.String.pipe(Schema.check(Schema.isPattern(/^[a-f0-9]{40}$/, { message: 'Expected a 40-character commit SHA' })));
const Version = Schema.String.pipe(
	Schema.check(Schema.isPattern(/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/, { message: 'Expected a release version without build metadata' })),
);

const ReleaseContext = Schema.Struct({
	repository: Schema.Literal(REPOSITORY),
	repositoryId: Schema.Union([Schema.Int, Schema.String]),
	operation: Schema.Literal('promote'),
	stream: Schema.Literal('main'),
	sourceSha: Sha,
	version: Version,
	draftRelease: Schema.Struct({ id: Schema.Int, tag: Schema.String }),
});
type ReleaseContext = typeof ReleaseContext.Type;

const Manifest = Schema.Struct({ package: Schema.Struct({ name: Schema.String, version: Schema.String }) });
const VcsInfo = Schema.Struct({ git: Schema.Struct({ sha1: Schema.String, dirty: Schema.optionalKey(Schema.Boolean) }) });
const Commit = Schema.Struct({ sha: Schema.String, commit: Schema.Struct({ verification: Schema.Struct({ verified: Schema.Boolean }) }) });
const WorkflowRun = Schema.Struct({
	id: Schema.Int,
	run_attempt: Schema.Int,
	head_sha: Schema.String,
	head_branch: Schema.NullOr(Schema.String),
	event: Schema.String,
	status: Schema.String,
	conclusion: Schema.NullOr(Schema.String),
	html_url: Schema.String,
});
const WorkflowRuns = Schema.Struct({ workflow_runs: Schema.Array(WorkflowRun) });
const GitObject = Schema.Struct({ object: Schema.Struct({ type: Schema.String, sha: Schema.String }) });
const RegistryEntry = Schema.Struct({ crate: Schema.String, num: Schema.String, yanked: Schema.Boolean, checksum: Schema.String });
type RegistryEntry = typeof RegistryEntry.Type;
const RegistryVersion = Schema.Struct({ version: RegistryEntry });
const Command = Schema.Literals(['check', 'candidate', 'crate-report']);

const require = (condition: boolean, message: string) => (condition ? Effect.void : Effect.fail(new ReleaseRejected({ message })));

const parseToml = (source: string, label: string) =>
	Effect.try({
		try: () => Bun.TOML.parse(source),
		catch: (cause) => new InvalidArchive({ message: `${label} is not valid TOML: ${String(cause)}` }),
	});

const decode = <S extends Schema.Top>(schema: S, label: string) => (input: unknown) =>
	Schema.decodeUnknownEffect(schema)(input).pipe(Effect.mapError((error) => new InvalidContext({ message: `${label}: ${error.message}` })));

const run = Effect.fn('run')(function*(command: string, args: ReadonlyArray<string>) {
	const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
	const label = [command, ...args].join(' ');
	const failed = (cause: unknown) => new CommandFailed({ message: `${label}: ${String(cause)}` });
	const handle = yield* spawner.spawn(ChildProcess.make(command, [...args])).pipe(Effect.mapError(failed));
	const [stdout, stderr] = yield* Effect.all([
		handle.stdout.pipe(Stream.decodeText(), Stream.mkString),
		handle.stderr.pipe(Stream.decodeText(), Stream.mkString),
	], { concurrency: 2 }).pipe(Effect.mapError(failed));
	const exitCode = yield* handle.exitCode.pipe(Effect.mapError(failed));
	if (exitCode !== ChildProcessSpawner.ExitCode(0)) {
		return yield* new CommandFailed({ message: `${label} exited with ${exitCode}: ${stderr.trim()}` });
	}
	return stdout;
}, Effect.scoped);

const fetchJson = Effect.fn('fetchJson')(function*<S extends Schema.Top>(
	request: HttpClientRequest.HttpClientRequest,
	schema: S,
	label: string,
) {
	const client = yield* HttpClient.HttpClient;
	const failed = (cause: { readonly message: string }) => new RequestFailed({ message: `${label}: ${cause.message}` });
	const response = yield* client.execute(request).pipe(Effect.mapError(failed));
	if (response.status === 404) {
		return Option.none<S['Type']>();
	}
	const ok = yield* HttpClientResponse.filterStatusOk(response).pipe(Effect.mapError(failed));
	const body = yield* HttpClientResponse.schemaBodyJson(schema)(ok).pipe(Effect.mapError(failed));
	return Option.some(body);
});

const github = Effect.fn('github')(function*<S extends Schema.Top>(path: string, schema: S) {
	const token = yield* Config.Redacted('GH_TOKEN').pipe(Effect.mapError(() => new InvalidContext({ message: 'GH_TOKEN is unset' })));
	const request = HttpClientRequest.get(`https://api.github.com/${path}`).pipe(
		HttpClientRequest.bearerToken(Redacted.value(token)),
		HttpClientRequest.setHeaders({ Accept: 'application/vnd.github+json', 'User-Agent': USER_AGENT, 'X-GitHub-Api-Version': '2026-03-10' }),
	);
	return yield* fetchJson(request, schema, `GitHub ${path}`);
});

const githubRequired = Effect.fn('githubRequired')(function*<S extends Schema.Top>(path: string, schema: S) {
	const body = yield* github(path, schema);
	if (Option.isNone(body)) {
		return yield* new RequestFailed({ message: `GitHub ${path}: not found` });
	}
	return body.value;
});

const env = (name: string) => Config.NonEmptyString(name).pipe(Effect.mapError(() => new InvalidContext({ message: `${name} is unset or empty` })));

const contextFromCheckout = Effect.fn('contextFromCheckout')(function*() {
	const context = yield* env('RELEASE_CONTEXT').pipe(Effect.flatMap(decode(Schema.fromJsonString(ReleaseContext), 'RELEASE_CONTEXT')));
	const manifest = yield* run('git', ['show', `${context.sourceSha}:Cargo.toml`]).pipe(
		Effect.flatMap((source) => parseToml(source, 'Cargo.toml')),
		Effect.flatMap(decode(Manifest, 'Cargo.toml')),
	);
	const repository = yield* env('GITHUB_REPOSITORY');
	const repositoryId = yield* env('GITHUB_REPOSITORY_ID');
	yield* require(repository === REPOSITORY, 'Repository mismatch');
	yield* require(String(context.repositoryId) === repositoryId, 'Repository ID mismatch');
	yield* require(manifest.package.name === CRATE, 'Unexpected crate');
	yield* require(context.version === manifest.package.version, 'Manifest version differs from approval');
	yield* require(context.draftRelease.tag === `v${context.version}`, 'Draft release tag differs from the approved version');
	return context;
});

const check = Effect.fn('check')(function*(context: ReleaseContext) {
	const sha = context.sourceSha;
	const commit = yield* githubRequired(`repos/${REPOSITORY}/commits/${sha}`, Commit);
	yield* require(commit.sha === sha, 'Commit identity mismatch');
	yield* require(commit.commit.verification.verified, 'Release commit has no verified signature');
	for (const workflow of ['ci.yml']) {
		const { workflow_runs } = yield* githubRequired(
			`repos/${REPOSITORY}/actions/workflows/${workflow}/runs?head_sha=${sha}&branch=master&event=push&per_page=100`,
			WorkflowRuns,
		);
		const candidates = workflow_runs.filter((run) => run.head_sha === sha && run.head_branch === 'master' && run.event === 'push');
		const latest = candidates.reduce<typeof WorkflowRun.Type | undefined>(
			(best, run) => (best === undefined || run.id > best.id || (run.id === best.id && run.run_attempt > best.run_attempt) ? run : best),
			undefined,
		);
		if (latest === undefined) {
			return yield* new ReleaseRejected({ message: `No master push run for ${workflow} at ${sha}` });
		}
		yield* require(
			latest.status === 'completed' && latest.conclusion === 'success',
			`${workflow} must succeed on the approved commit: ${latest.html_url}`,
		);
	}
});

const archiveDigest = Effect.fn('archiveDigest')(function*(path: string, context: ReleaseContext) {
	const fs = yield* FileSystem.FileSystem;
	const bytes = yield* fs.readFile(path).pipe(Effect.mapError((error) => new InvalidArchive({ message: error.message })));
	const prefix = `${CRATE}-${context.version}`;
	const files = yield* Effect.tryPromise({
		try: () => new Bun.Archive(bytes).files(),
		catch: (cause) => new InvalidArchive({ message: `${path} is not a readable crate archive: ${String(cause)}` }),
	});
	const entry = Effect.fn('entry')(function*(name: string) {
		const file = files.get(`${prefix}/${name}`);
		if (file === undefined) {
			return yield* new InvalidArchive({ message: `${path} has no ${prefix}/${name}` });
		}
		return yield* Effect.tryPromise({
			try: () => file.text(),
			catch: (cause) => new InvalidArchive({ message: `${prefix}/${name} is unreadable: ${String(cause)}` }),
		});
	});
	const vcs = yield* entry('.cargo_vcs_info.json').pipe(Effect.flatMap(decode(Schema.fromJsonString(VcsInfo), '.cargo_vcs_info.json')));
	const manifest = yield* entry('Cargo.toml').pipe(
		Effect.flatMap((source) => parseToml(source, 'Archived Cargo.toml')),
		Effect.flatMap(decode(Manifest, 'Archived Cargo.toml')),
	);
	yield* require(vcs.git.sha1 === context.sourceSha, 'Archive commit mismatch');
	yield* require(vcs.git.dirty !== true, 'Archive contains uncommitted changes');
	yield* require(manifest.package.name === CRATE && manifest.package.version === context.version, 'Archive version mismatch');
	return new Bun.CryptoHasher('sha256').update(bytes).digest('hex');
});

const registryVersion = Effect.fn('registryVersion')(function*(version: string) {
	const request = HttpClientRequest.get(`https://crates.io/api/v1/crates/${CRATE}/${version}`).pipe(
		HttpClientRequest.setHeader('User-Agent', USER_AGENT),
	);
	const body = yield* fetchJson(request, RegistryVersion, 'crates.io');
	return Option.map(body, ({ version }) => version);
});

const validateRegistry = (entry: Option.Option<RegistryEntry>, version: string, digest: string) =>
	Option.match(entry, {
		onNone: () => Effect.fail(new ReleaseRejected({ message: 'Published crate version is not visible in the registry' })),
		onSome: (published) =>
			require(
				published.crate === CRATE && published.num === version && !published.yanked && published.checksum === digest,
				'Existing registry publication differs from the verified archive',
			),
	});

const versionTag = Effect.fn('versionTag')(function*(context: ReleaseContext) {
	const tag = `v${context.version}`;
	const ref = yield* github(`repos/${REPOSITORY}/git/ref/tags/${tag}`, GitObject);
	if (Option.isNone(ref)) {
		return;
	}
	yield* require(ref.value.object.type === 'tag', 'Release tag must be annotated');
	const target = yield* githubRequired(`repos/${REPOSITORY}/git/tags/${ref.value.object.sha}`, GitObject);
	yield* require(target.object.type === 'commit' && target.object.sha === context.sourceSha, 'Release tag points to another commit');
});

const output = Effect.fn('output')(function*(key: string, value: string) {
	const fs = yield* FileSystem.FileSystem;
	const path = yield* env('GITHUB_OUTPUT');
	yield* fs.writeFileString(path, `${key}=${value}\n`, { flag: 'a' }).pipe(Effect.mapError((error) => new CommandFailed({ message: error.message })));
});

const main = Effect.gen(function*() {
	const command = yield* decode(Command, 'command')(process.argv[2]);
	const context = yield* contextFromCheckout();
	if (command === 'check') {
		return yield* check(context);
	}
	const digest = yield* archiveDigest(`target/package/${CRATE}-${context.version}.crate`, context);
	const entry = yield* registryVersion(context.version);
	if (Option.isSome(entry) || command === 'crate-report') {
		yield* validateRegistry(entry, context.version, digest);
	}
	if (command === 'candidate') {
		yield* versionTag(context);
		return yield* output('publish', String(Option.isNone(entry)));
	}
	const publication = {
		id: `cargo:${CRATE}`,
		manager: 'cargo',
		name: CRATE,
		version: context.version,
		outcome: 'succeeded',
		required: true,
		digest,
	};
	yield* output('publications', JSON.stringify([publication]));
});

main.pipe(
	Effect.tapError((error) =>
		Console.error(`::error title=${error._tag}::${error.message.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A')}`)
	),
	Effect.provide(Layer.mergeAll(BunServices.layer, FetchHttpClient.layer)),
	BunRuntime.runMain({ disableErrorReporting: true }),
);
