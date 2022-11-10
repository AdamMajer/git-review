import { spawn } from 'node:child_process'

const CommitText = Symbol('Commit Text');
const GpgSigIndexes = Symbol('GPG Sig Indexes');

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
			const commit_data = data.map(d => d.toString('utf-8')).join('').split('\n');

			// parse headers and data
			const obj = {};
			let header = '';
			let gpg_start_idx = -1, gpg_end_idx = -1;

			const offsetInRawHeader = function(lines, idx) {
				return lines.slice(0, idx).join('\n').length + 1;
			}

			for (let i=0; i<commit_data.length; i++) {
				const d = commit_data[i];
				if (d.length === 0) {
					obj[CommitText] = commit_data.slice(i+1).join('\n');
					if (gpg_start_idx > gpg_end_idx)
						gpg_end_idx = offsetInRawHeader(commit_data, i) - 1;

					obj[GpgSigIndexes] = [gpg_start_idx, gpg_end_idx];
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

			accepted([commit_data.join('\n'), obj]);
		});
	})
}

export {
	CommitText,
	GpgSigIndexes,
	ParseCommit
}
