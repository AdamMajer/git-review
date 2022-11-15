import { spawn } from 'node:child_process'

const CommitText = Symbol('Commit Text');
const GpgSigIdx = Symbol('GPG Sig Indexes');
const SignedData = Symbol('SignedData');

function ParseCommit(hash) {
	return new Promise((accepted, rejected) => {
		const commit = spawn('git', ['cat-file', '-p', hash], {});
		commit.on("error", err => {
			rejected(err);
		});

		const data = []
		commit.stdout.on('data', d => {
			data.push(d);
		});
		commit.stdout.on('end', () => {
			const raw_data = data.map(d => d.toString('utf-8')).join('');
			const commit_data = raw_data.split('\n');

			// parse headers and data
			const obj = {};
			let header = '';
			let gpg_start_idx = -1, gpg_end_idx = -1;

			const offsetInRawHeader = function(lines, idx) {
				return lines.slice(0, idx).join('\n').length + 1; // include EOL of final line
			}

			for (let i=0; i<commit_data.length; i++) {
				const d = commit_data[i];
				if (d.length === 0) {
					obj[CommitText] = commit_data.slice(i+1).join('\n');
					if (gpg_start_idx === -1) {
						gpg_start_idx = offsetInRawHeader(commit_data, i);
						gpg_end_idx = gpg_start_idx;
					}
					if (gpg_start_idx > gpg_end_idx)
						gpg_end_idx = offsetInRawHeader(commit_data, i); // don't include the EOL character

					obj[GpgSigIdx] = gpg_start_idx;
					break;
				}
				else if(d.charAt(0) === ' ') {
					if (header.length === 0) {
						rejected('Error parsing commit on line %s. Multi-line without header?');
						return;
					}
					obj[header] = obj[header] + '\n' + d.slice(1);
				}
				else {
					const header_idx = d.indexOf(' ');
					header = d.slice(0, header_idx);
					obj[header] = d.slice(header_idx+1);

					if (header === 'gpgsig')
						gpg_start_idx = offsetInRawHeader(commit_data, i); // ASSUME that sig is not first header, ever
					else if (gpg_start_idx > gpg_end_idx)
						gpg_end_idx = offsetInRawHeader(commit_data, i);
				}
			}


			if (gpg_start_idx > 0)
				obj[SignedData] = raw_data.slice(0, gpg_start_idx) + raw_data.slice(gpg_end_idx);
			else
				obj[SignedData] = raw_data;

			accepted(obj);
		});
	})
}

function RawCommit(commit) {
	const gpgsig = commit['gpgsig'];
	if (!gpgsig || gpgsig.length === 0)
		return commit[SignedData];

	const d = commit[SignedData];
	const whitespace_prepended_gpgsig = gpgsig.split('\n').map(line => ' ' + line).join('\n');
	return d.slice(0, commit[GpgSigIdx]) +
	       'gpgsig' + whitespace_prepended_gpgsig + '\n' +
	       d.slice(commit[GpgSigIdx]);
}

function CommitCommit(commit) {
	return new Promise((resolved, rejected) => {
		const stdout = [];
		const git = spawn('git', ['hash-object', '-t', 'commit', '-w', '--stdin', '--no-filters'], {stdio: ['pipe', 'pipe', 'inherit']});
		git.stdin.end(RawCommit(commit));
		git.stdout.on('data', d => stdout.push(d));
		git.on("error", err => {
			rejected(err);
		});
		git.on('exit', (code) => {
			if (code === 0) {
				let hashid = stdout.join('').toString('utf-8');
				resolved(hashid);
				return;
			}

			console.error('git returned error code %d on exit', code);
			rejected('git error on saving commit');
		})
	})
}

export {
	CommitText,
	GpgSigIdx,
	SignedData,

	CommitCommit,
	ParseCommit
}
