// Image upload Worker for the Autism Allyship Foundation. Receives resized
// images from the admin panel and commits them to the website repository
// through the GitHub API. Only signed in admins may upload: the Firebase ID
// token sent with the request is verified against Google's public keys
// before anything is written to GitHub.

interface Env {
	GITHUB_TOKEN: string;
	GITHUB_OWNER: string;
	GITHUB_REPO: string;
	GITHUB_BRANCH: string;
	ADMIN_UIDS: string;
}

interface UploadedFile {
	data: string; // base64 encoded file content
	type: string; // mime type, e.g. image/webp
	thumb?: boolean; // when true, name the file with a -thumb suffix
}

interface UploadRequest {
	folder: string; // e.g. "assets/uploads/blog/"
	files: UploadedFile[];
	commitMessage: string;
	branch?: string; // where the admin panel is running, when it is not production
}

interface RemoveRequest {
	paths: string[]; // e.g. ["assets/uploads/blog/img-abc.webp"]
	branch?: string;
}

// The upload endpoint answers at /upload rather than the root because the
// static files in public/ are served ahead of this script for any path they
// cover, and the root is one of them. A POST to the root is answered by the
// asset layer with a 405 and never reaches this code at all.
const UPLOAD_PATH = '/upload';
const REMOVE_PATH = '/remove';

const ALLOWED_PREFIX = 'assets/uploads/';
// Production handover, 3 September 2026: main only. Until then this also
// accepted staging and dev so the preview admins could upload to their own
// branch. The Worker holds a GitHub token with full repo scope, so once the
// foundation owns the site there is no reason for an admin page to be able to
// write anywhere except production. The admin helper stopped asking for a
// branch at the same time, but the check that matters is this one: it is the
// only side the client cannot talk its way past.
const ALLOWED_BRANCHES = ['main'];
const EXTENSIONS: Record<string, string> = {
	'image/webp': '.webp',
	'image/jpeg': '.jpg',
	'image/jpg': '.jpg',
	'image/png': '.png',
	'image/gif': '.gif',
	'application/pdf': '.pdf',
};
const MAX_FILES = 10;
const MAX_REMOVE_PATHS = 20;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 20 * 1024 * 1024;

const PROJECT_ID = 'autism-allyship';
const JWKS_URL = 'https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com';

// Google serves the outgoing and incoming keys together when it rotates, so
// an hour in memory spares a fetch on every upload and still picks a
// rotation up the same day.
const JWKS_CACHE_MS = 60 * 60 * 1000;
type SigningKey = JsonWebKey & { kid?: string };
let jwksCache: { keys: SigningKey[]; fetchedAt: number } | null = null;

// Returns the request's origin when it belongs to this project, an empty
// string when it does not, and null when there is no Origin header at all,
// which means the call did not come from a browser.
function allowedOrigin(request: Request): string | null {
	const origin = request.headers.get('Origin');
	if (!origin) {
		return null;
	}
	const ours =
		origin === 'https://autism-allyship.pages.dev' ||
		origin.endsWith('.autism-allyship.pages.dev') ||
		origin === 'http://localhost:5500' ||
		origin === 'http://127.0.0.1:5500';
	return ours ? origin : '';
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const origin = allowedOrigin(request);

		if (request.method === 'OPTIONS') {
			if (origin === '') {
				return json({ error: 'Not allowed' }, 403, origin);
			}
			return new Response(null, { status: 204, headers: corsHeaders(origin) });
		}

		if (request.method !== 'POST') {
			return json({ error: 'Method not allowed' }, 405, origin);
		}

		const pathname = new URL(request.url).pathname;
		if (pathname !== UPLOAD_PATH && pathname !== REMOVE_PATH) {
			return json({ error: 'Not found' }, 404, origin);
		}

		if (origin === '') {
			return json({ error: 'Not allowed' }, 403, origin);
		}

		let adminUid: string | null = null;
		try {
			adminUid = await verifyAdmin(request, env);
		} catch (error) {
			console.error('Token check failed:', error);
		}
		if (!adminUid) {
			return json({ error: 'Sign in as an admin to upload images' }, 401, origin);
		}

		if (pathname === REMOVE_PATH) {
			let body: RemoveRequest;
			try {
				body = (await request.json()) as RemoveRequest;
			} catch {
				return json({ error: 'Invalid JSON body' }, 400, origin);
			}

			if (!Array.isArray(body.paths) || body.paths.length === 0) {
				return json({ error: 'No files to remove' }, 400, origin);
			}
			if (body.paths.length > MAX_REMOVE_PATHS) {
				return json({ error: 'Too many files to remove at once' }, 400, origin);
			}
			for (const path of body.paths) {
				if (typeof path !== 'string' || !path.startsWith(ALLOWED_PREFIX) || path.includes('..')) {
					return json({ error: 'Paths must be inside assets/uploads/' }, 400, origin);
				}
			}

			const branch = body.branch || env.GITHUB_BRANCH;
			if (!ALLOWED_BRANCHES.includes(branch)) {
				return json({ error: 'Files can only be removed from main' }, 400, origin);
			}

			try {
				const removed = await removeFiles(env, branch, body.paths);
				return json({ ok: true, removed }, 200, origin);
			} catch (error) {
				console.error('Removal failed:', error);
				return json({ error: 'Removal failed. Try again.' }, 500, origin);
			}
		}

		let body: UploadRequest;
		try {
			body = (await request.json()) as UploadRequest;
		} catch {
			return json({ error: 'Invalid JSON body' }, 400, origin);
		}

		if (!body.folder || !body.folder.startsWith(ALLOWED_PREFIX) || body.folder.includes('..')) {
			return json({ error: 'Folder must be inside assets/uploads/' }, 400, origin);
		}

		if (!body.files || body.files.length === 0) {
			return json({ error: 'No files to upload' }, 400, origin);
		}
		if (body.files.length > MAX_FILES) {
			return json({ error: 'Too many files in one upload' }, 400, origin);
		}

		let totalBytes = 0;
		for (const file of body.files) {
			if (!file.data || !file.type) {
				return json({ error: 'Each file needs data and a type' }, 400, origin);
			}
			if (!EXTENSIONS[file.type]) {
				return json({ error: 'Only image or PDF files can be uploaded' }, 400, origin);
			}
			const bytes = Math.floor((file.data.length * 3) / 4);
			if (bytes > MAX_FILE_BYTES) {
				return json({ error: 'One of the files is too large after resizing. Try a smaller image.' }, 413, origin);
			}
			totalBytes += bytes;
		}
		if (totalBytes > MAX_TOTAL_BYTES) {
			return json({ error: 'The whole upload is too large. Upload fewer images at once.' }, 413, origin);
		}

		const branch = body.branch || env.GITHUB_BRANCH;
		if (!ALLOWED_BRANCHES.includes(branch)) {
			return json({ error: 'Images can only be uploaded to main' }, 400, origin);
		}

		try {
			const result = await commitFiles(env, branch, body.folder, body.files, body.commitMessage || 'Upload images');
			return json({ ok: true, ...result }, 200, origin);
		} catch (error) {
			console.error('Upload failed:', error);
			return json({ error: 'Upload failed. Try again.' }, 500, origin);
		}
	},
};

// Checks the Firebase ID token the way the Firebase documentation describes:
// RS256 signature against Google's public keys, then issuer, audience,
// expiry, and the uid against the admin list in the ADMIN_UIDS secret.
// Returns the admin's uid, or null for anything wrong with the token.
async function verifyAdmin(request: Request, env: Env): Promise<string | null> {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return null;
	}

	const token = authHeader.slice('Bearer '.length);
	const parts = token.split('.');
	if (parts.length !== 3) {
		return null;
	}

	const header = decodeJson(parts[0]);
	const payload = decodeJson(parts[1]);
	if (!header || !payload) {
		return null;
	}
	if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
		return null;
	}

	const keys = await fetchJwks();
	const jwk = keys.find((key) => key.kid === header.kid);
	if (!jwk) {
		return null;
	}

	const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
	const signatureOk = await crypto.subtle.verify(
		'RSASSA-PKCS1-v1_5',
		key,
		decodeBase64Url(parts[2]),
		new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
	);
	if (!signatureOk) {
		return null;
	}

	if (payload.iss !== `https://securetoken.google.com/${PROJECT_ID}`) {
		return null;
	}
	if (payload.aud !== PROJECT_ID) {
		return null;
	}
	if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) {
		return null;
	}
	if (typeof payload.sub !== 'string' || payload.sub === '') {
		return null;
	}

	const admins = (env.ADMIN_UIDS || '').split(',').map((uid) => uid.trim());
	if (!admins.includes(payload.sub)) {
		return null;
	}
	return payload.sub;
}

async function fetchJwks(): Promise<SigningKey[]> {
	if (jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_CACHE_MS) {
		return jwksCache.keys;
	}
	const response = await fetch(JWKS_URL);
	if (!response.ok) {
		throw new Error('Could not load the token signing keys: ' + response.status);
	}
	const data = (await response.json()) as { keys: SigningKey[] };
	jwksCache = { keys: data.keys, fetchedAt: Date.now() };
	return data.keys;
}

// Commits all files in one commit using the GitHub Git Data API, so a whole
// upload counts as a single deploy on Cloudflare Pages. Filenames carry a
// timestamp and a random tail because a fixed name would have every new
// image overwrite the previous one.
async function commitFiles(env: Env, branch: string, folder: string, files: UploadedFile[], commitMessage: string) {
	const owner = env.GITHUB_OWNER;
	const repo = env.GITHUB_REPO;
	const token = env.GITHUB_TOKEN;

	const headers = {
		Authorization: 'Bearer ' + token,
		Accept: 'application/vnd.github+json',
		'Content-Type': 'application/json',
		'User-Agent': 'autism-allyship-upload-worker',
	};

	const api = 'https://api.github.com';
	const basePath = `${api}/repos/${owner}/${repo}`;

	const refRes = await fetch(`${basePath}/git/ref/heads/${branch}`, { headers });
	if (!refRes.ok) {
		throw new Error('Failed to get branch ref: ' + refRes.status);
	}
	const refData = (await refRes.json()) as { object: { sha: string } };
	const parentCommitSha = refData.object.sha;

	const commitRes = await fetch(`${basePath}/git/commits/${parentCommitSha}`, { headers });
	if (!commitRes.ok) {
		throw new Error('Failed to get commit: ' + commitRes.status);
	}
	const commitData = (await commitRes.json()) as { tree: { sha: string } };
	const baseTreeSha = commitData.tree.sha;

	const stamp = Date.now().toString(36);
	const treeEntries: { path: string; mode: string; type: string; sha: string }[] = [];
	const paths: string[] = [];
	let lastId = '';

	for (const file of files) {
		const extension = EXTENSIONS[file.type];
		// Posters and photos keep the img- prefix. PDFs, the only non-image type
		// accepted, get doc- instead, so a folder listing tells the two apart.
		const prefix = file.type === 'application/pdf' ? 'doc' : 'img';
		if (!file.thumb) {
			lastId = `${stamp}-${crypto.randomUUID().replace(/-/g, '').slice(0, 6)}`;
		}
		const filename = file.thumb ? `${prefix}-${lastId}-thumb${extension}` : `${prefix}-${lastId}${extension}`;
		const path = folder + filename;

		const blobRes = await fetch(`${basePath}/git/blobs`, {
			method: 'POST',
			headers,
			body: JSON.stringify({
				content: file.data,
				encoding: 'base64',
			}),
		});
		if (!blobRes.ok) {
			throw new Error('Failed to create blob: ' + blobRes.status);
		}
		const blobData = (await blobRes.json()) as { sha: string };

		treeEntries.push({
			path,
			mode: '100644',
			type: 'blob',
			sha: blobData.sha,
		});
		paths.push(path);
	}

	const treeRes = await fetch(`${basePath}/git/trees`, {
		method: 'POST',
		headers,
		body: JSON.stringify({
			base_tree: baseTreeSha,
			tree: treeEntries,
		}),
	});
	if (!treeRes.ok) {
		throw new Error('Failed to create tree: ' + treeRes.status);
	}
	const treeData = (await treeRes.json()) as { sha: string };

	const newCommitRes = await fetch(`${basePath}/git/commits`, {
		method: 'POST',
		headers,
		body: JSON.stringify({
			message: commitMessage,
			tree: treeData.sha,
			parents: [parentCommitSha],
		}),
	});
	if (!newCommitRes.ok) {
		throw new Error('Failed to create commit: ' + newCommitRes.status);
	}
	const newCommitData = (await newCommitRes.json()) as { sha: string };

	const updateRes = await fetch(`${basePath}/git/refs/heads/${branch}`, {
		method: 'PATCH',
		headers,
		body: JSON.stringify({
			sha: newCommitData.sha,
			force: false,
		}),
	});
	if (!updateRes.ok) {
		throw new Error('Failed to update branch: ' + updateRes.status);
	}

	return { commitSha: newCommitData.sha, files: paths.map((path) => ({ path })) };
}

// Removes files in one commit, mirroring how uploads are batched. A tree
// entry with a null sha deletes the file, and a path that is not in the tree
// is simply ignored by GitHub, so asking twice does no harm.
async function removeFiles(env: Env, branch: string, paths: string[]): Promise<string[]> {
	const owner = env.GITHUB_OWNER;
	const repo = env.GITHUB_REPO;
	const token = env.GITHUB_TOKEN;

	const headers = {
		Authorization: 'Bearer ' + token,
		Accept: 'application/vnd.github+json',
		'Content-Type': 'application/json',
		'User-Agent': 'autism-allyship-upload-worker',
	};

	const api = 'https://api.github.com';
	const basePath = `${api}/repos/${owner}/${repo}`;

	const refRes = await fetch(`${basePath}/git/ref/heads/${branch}`, { headers });
	if (!refRes.ok) {
		throw new Error('Failed to get branch ref: ' + refRes.status);
	}
	const refData = (await refRes.json()) as { object: { sha: string } };
	const parentCommitSha = refData.object.sha;

	const commitRes = await fetch(`${basePath}/git/commits/${parentCommitSha}`, { headers });
	if (!commitRes.ok) {
		throw new Error('Failed to get commit: ' + commitRes.status);
	}
	const commitData = (await commitRes.json()) as { tree: { sha: string } };
	const baseTreeSha = commitData.tree.sha;

	const treeEntries = paths.map((path) => ({
		path,
		mode: '100644',
		type: 'blob',
		sha: null,
	}));

	const treeRes = await fetch(`${basePath}/git/trees`, {
		method: 'POST',
		headers,
		body: JSON.stringify({
			base_tree: baseTreeSha,
			tree: treeEntries,
		}),
	});
	if (!treeRes.ok) {
		throw new Error('Failed to create tree: ' + treeRes.status);
	}
	const treeData = (await treeRes.json()) as { sha: string };

	const newCommitRes = await fetch(`${basePath}/git/commits`, {
		method: 'POST',
		headers,
		body: JSON.stringify({
			message: 'Remove uploaded images',
			tree: treeData.sha,
			parents: [parentCommitSha],
		}),
	});
	if (!newCommitRes.ok) {
		throw new Error('Failed to create commit: ' + newCommitRes.status);
	}
	const newCommitData = (await newCommitRes.json()) as { sha: string };

	const updateRes = await fetch(`${basePath}/git/refs/heads/${branch}`, {
		method: 'PATCH',
		headers,
		body: JSON.stringify({
			sha: newCommitData.sha,
			force: false,
		}),
	});
	if (!updateRes.ok) {
		throw new Error('Failed to update branch: ' + updateRes.status);
	}

	return paths;
}

function decodeBase64Url(part: string): ArrayBuffer {	const binary = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

function decodeJson(part: string): any {
	try {
		return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')));
	} catch {
		return null;
	}
}

function corsHeaders(origin: string | null): Record<string, string> {
	if (!origin) {
		return {};
	}
	return {
		'Access-Control-Allow-Origin': origin,
		'Access-Control-Allow-Methods': 'POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		'Access-Control-Max-Age': '86400',
	};
}

// Errors carry the CORS headers too, so the admin panel can read what went
// wrong instead of the browser hiding the response behind a CORS error.
function json(data: unknown, status: number, origin: string | null): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...corsHeaders(origin),
		},
	});
}
