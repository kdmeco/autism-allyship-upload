import { env, createExecutionContext, waitOnExecutionContext, fetchMock } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import worker from '../src';

// The token checks are tested with a real RSA key pair: the public half is
// served from a mocked copy of Google's key endpoint, the private half signs
// the test tokens. The GitHub calls are mocked so no test touches the real
// repository.

const testEnv = {
	GITHUB_TOKEN: 'test-token',
	GITHUB_OWNER: 'kdmeco',
	GITHUB_REPO: 'autism-allyship',
	GITHUB_BRANCH: 'main',
	ADMIN_UIDS: 'admin-uid',
	...env,
};

const JWKS_PATH = '/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com';

let signingKey: CryptoKey;
let verifyingJwk: JsonWebKey & { kid: string };

beforeAll(async () => {
	const pair = (await crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
		true,
		['sign', 'verify'],
	)) as CryptoKeyPair;
	signingKey = pair.privateKey;
	verifyingJwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid: 'test-key' };

	fetchMock.activate();
	fetchMock.disableNetConnect();
	fetchMock.get('https://www.googleapis.com').intercept({ path: JWKS_PATH }).reply(200, { keys: [verifyingJwk] }).persist();
	fetchMock
		.get('https://api.github.com')
		.intercept({ path: /\/repos\/kdmeco\/autism-allyship\/git\/.*/, method: /.*/ })
		.reply(200, { sha: 'new-sha', object: { sha: 'ref-sha' }, tree: { sha: 'tree-sha' } })
		.persist();
});

function toBase64Url(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeJson(value: unknown): string {
	return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function mintToken(claims: Record<string, unknown>): Promise<string> {
	const header = encodeJson({ alg: 'RS256', kid: verifyingJwk.kid });
	const payload = encodeJson({
		iss: 'https://securetoken.google.com/autism-allyship',
		aud: 'autism-allyship',
		exp: Math.floor(Date.now() / 1000) + 3600,
		sub: 'admin-uid',
		...claims,
	});
	const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signingKey, new TextEncoder().encode(`${header}.${payload}`));
	return `${header}.${payload}.${toBase64Url(new Uint8Array(signature))}`;
}

function uploadBody(overrides: Record<string, unknown> = {}): string {
	return JSON.stringify({
		folder: 'assets/uploads/blog/',
		commitMessage: 'Upload blog image',
		files: [
			{ data: 'AAAA', type: 'image/webp' },
			{ data: 'AAAA', type: 'image/webp', thumb: true },
		],
		...overrides,
	});
}

async function post(body: string, headers: Record<string, string> = {}, path = '/upload'): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await worker.fetch(
		new Request('https://worker' + path, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', ...headers },
			body,
		}),
		testEnv,
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

describe('the upload worker', () => {
	it('rejects a request without a token', async () => {
		const response = await post(uploadBody());
		expect(response.status).toBe(401);
	});

	it('rejects a token that is not a jwt', async () => {
		const response = await post(uploadBody(), { Authorization: 'Bearer not.a.token' });
		expect(response.status).toBe(401);
	});

	it('rejects an expired token', async () => {
		const token = await mintToken({ exp: Math.floor(Date.now() / 1000) - 60 });
		const response = await post(uploadBody(), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(401);
	});

	it('rejects a token issued for another project', async () => {
		const token = await mintToken({ iss: 'https://securetoken.google.com/someone-else', aud: 'someone-else' });
		const response = await post(uploadBody(), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(401);
	});

	it('rejects a token whose signature was made with the wrong key', async () => {
		const stranger = (await crypto.subtle.generateKey(
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
			true,
			['sign', 'verify'],
		)) as CryptoKeyPair;
		const header = encodeJson({ alg: 'RS256', kid: verifyingJwk.kid });
		const payload = encodeJson({ iss: 'https://securetoken.google.com/autism-allyship', aud: 'autism-allyship', exp: Math.floor(Date.now() / 1000) + 3600, sub: 'admin-uid' });
		const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', stranger.privateKey, new TextEncoder().encode(`${header}.${payload}`));
		const response = await post(uploadBody(), { Authorization: `Bearer ${header}.${payload}.${toBase64Url(new Uint8Array(signature))}` });
		expect(response.status).toBe(401);
	});

	it('rejects a signed in user who is not an admin', async () => {
		const token = await mintToken({ sub: 'someone-else' });
		const response = await post(uploadBody(), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(401);
	});

	it('rejects a folder outside the uploads directory', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ folder: '../outside/' }), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(400);
	});

	it('rejects a folder that climbs out with dot dot', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ folder: 'assets/uploads/blog/../../admin/' }), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(400);
	});

	it('rejects a file type that is not an image', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ files: [{ data: 'AAAA', type: 'text/html' }] }), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(400);
	});

	it('rejects more than ten files in one upload', async () => {
		const token = await mintToken({});
		const files = Array.from({ length: 11 }, () => ({ data: 'AAAA', type: 'image/webp' }));
		const response = await post(uploadBody({ files }), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(400);
	});

	it('rejects a single file over five megabytes', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ files: [{ data: 'A'.repeat(7000000), type: 'image/webp' }] }), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(413);
	});

	it('rejects a branch outside the allowlist', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ branch: 'feat/evil' }), { Authorization: 'Bearer ' + token });
		expect(response.status).toBe(400);
	});

	it('answers 404 on the root path, which the asset layer owns', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody(), { Authorization: 'Bearer ' + token }, '/');
		expect(response.status).toBe(404);
	});

	it('refuses an origin that is not one of ours', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody(), { Authorization: 'Bearer ' + token, Origin: 'https://evil.example' });
		expect(response.status).toBe(403);
	});

	it('echoes a staging origin and commits for a signed in admin', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ branch: 'staging' }), {
			Authorization: 'Bearer ' + token,
			Origin: 'https://staging.autism-allyship.pages.dev',
		});
		expect(response.status).toBe(200);
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://staging.autism-allyship.pages.dev');

		const result = (await response.json()) as { ok: boolean; commitSha: string; files: { path: string }[] };
		expect(result.ok).toBe(true);
		expect(result.commitSha).toBe('new-sha');
		expect(result.files).toHaveLength(2);
		expect(result.files[0].path).toMatch(/^assets\/uploads\/blog\/img-[a-z0-9]+-[a-f0-9]{6}\.webp$/);
		expect(result.files[1].path).toMatch(/^assets\/uploads\/blog\/img-[a-z0-9]+-[a-f0-9]{6}-thumb\.webp$/);
		expect(result.files[1].path).toBe(result.files[0].path.replace('.webp', '-thumb.webp'));
	});

	it('gives two uploads different file names', async () => {
		const token = await mintToken({});
		const first = await post(uploadBody(), { Authorization: 'Bearer ' + token });
		const second = await post(uploadBody(), { Authorization: 'Bearer ' + token });
		const firstName = ((await first.json()) as { files: { path: string }[] }).files[0].path;
		const secondName = ((await second.json()) as { files: { path: string }[] }).files[0].path;
		expect(firstName).not.toBe(secondName);
	});

	it('accepts a pdf attachment and prefixes its filename with doc-', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ files: [{ data: 'AAAA', type: 'application/pdf' }] }), {
			Authorization: 'Bearer ' + token,
			Origin: 'https://staging.autism-allyship.pages.dev',
		});
		expect(response.status).toBe(200);
		const result = (await response.json()) as { ok: boolean; files: { path: string }[] };
		expect(result.ok).toBe(true);
		expect(result.files[0].path).toMatch(/^assets\/uploads\/blog\/doc-[a-z0-9]+-[a-f0-9]{6}\.pdf$/);
	});

	it('rejects a pdf over five megabytes, the same cap as an image', async () => {
		const token = await mintToken({});
		const response = await post(uploadBody({ files: [{ data: 'A'.repeat(7000000), type: 'application/pdf' }] }), {
			Authorization: 'Bearer ' + token,
		});
		expect(response.status).toBe(413);
	});

	it('removes files for a signed in admin', async () => {
		const token = await mintToken({});
		const response = await post(JSON.stringify({ paths: ['assets/uploads/blog/img-a.webp'] }), {
			Authorization: 'Bearer ' + token,
			Origin: 'https://staging.autism-allyship.pages.dev',
		}, '/remove');
		expect(response.status).toBe(200);
		const result = (await response.json()) as { ok: boolean; removed: string[] };
		expect(result.ok).toBe(true);
		expect(result.removed).toEqual(['assets/uploads/blog/img-a.webp']);
	});

	it('refuses removal without a token', async () => {
		const response = await post(JSON.stringify({ paths: ['assets/uploads/blog/img-a.webp'] }), {}, '/remove');
		expect(response.status).toBe(401);
	});

	it('refuses to remove a path outside the uploads directory', async () => {
		const token = await mintToken({});
		const response = await post(JSON.stringify({ paths: ['styles.css'] }), { Authorization: 'Bearer ' + token }, '/remove');
		expect(response.status).toBe(400);
	});

	it('refuses to remove a path that climbs out with dot dot', async () => {
		const token = await mintToken({});
		const response = await post(JSON.stringify({ paths: ['assets/uploads/../styles.css'] }), { Authorization: 'Bearer ' + token }, '/remove');
		expect(response.status).toBe(400);
	});

	it('refuses removal on a branch outside the allowlist', async () => {
		const token = await mintToken({});
		const response = await post(JSON.stringify({ paths: ['assets/uploads/blog/img-a.webp'], branch: 'feat/evil' }), { Authorization: 'Bearer ' + token }, '/remove');
		expect(response.status).toBe(400);
	});

	it('allows the authorization header in preflights', async () => {
		const ctx = createExecutionContext();
		const response = await worker.fetch(
			new Request('https://worker/upload', {
				method: 'OPTIONS',
				headers: {
					Origin: 'https://staging.autism-allyship.pages.dev',
					'Access-Control-Request-Method': 'POST',
					'Access-Control-Request-Headers': 'content-type, authorization',
				},
			}),
			testEnv,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(204);
		expect(response.headers.get('Access-Control-Allow-Headers')).toContain('Authorization');
		expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://staging.autism-allyship.pages.dev');
	});
});
