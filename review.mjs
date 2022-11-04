#!/usr/bin/node

import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'

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

function SigTimestampToDate(ts) {
	if (ts === '0')
		return undefined;

	if (Number(ts).toString() === ts) {
		return new Date(Number(ts) * 1000);
	}

	if (ts.includes('T'))
		return new Date(ts);

	throw "Unknown Timestamp format: " + ts;
}

function ParseErrorSigResult(res) {
	const res_data = res.split(' ');

	return {
		is_valid: false,
		is_missing: res_data[6] === '9',
		keyid: res_data[7],
		timestamp: SigTimestampToDate(res_data[5]),
	}
}

function ParseValidSigResult(res) {
	const res_data = res.split(' ');

	return {
		is_valid: true,
		is_missing: false,
		keyid: res_data[1],
		timestamp: SigTimestampToDate(res_data[3]),
		expires: SigTimestampToDate(res_data[4]),
	}
}

function ParseSigResults(result_string) {
	const gnupg_header = '[GNUPG:]';
	const newsig_header = 'NEWSIG';
	const errsig_header = 'ERRSIG';
	const validsig_header = 'VALIDSIG';

	const result_lines = result_string
		.split('\n')
		.filter(line => line.startsWith(gnupg_header))
		.map(line => line.slice(gnupg_header.length + 1))
		.filter(line => line.startsWith(newsig_header) || line.startsWith(validsig_header) || line.startsWith(errsig_header));

	if(result_lines.filter(r => r === newsig_header).length*2 != result_lines.length) {
		throw "Weird results. Should have one result per signature";
	}

	return result_lines.filter(r => r !== newsig_header).map(res => {
		if (res.startsWith(errsig_header))
			return ParseErrorSigResult(res);
		else if(res.startsWith(validsig_header))
			return ParseValidSigResult(res);

		throw "Unreachable";
	})
}

function ReadKeyringConfig() {
	const filename = 'keyrings.json';

	return readFile(filename, {encoding: 'utf-8'})
		.then(json_str => JSON.parse(json_str));
}

function CheckSignatures(keyring, raw_commit, headers) {
	const commit_msg = raw_commit.slice(0, headers[GpgSigIndexes][0]) + raw_commit.slice(headers[GpgSigIndexes][1]+1);
	const signature = headers.gpgsig;

	return new Promise((accepted, rejected) => {
		let status = [];

		const gpg_verify = spawn('gpgv2', ['--keyring', keyring.filename, '--status-fd', '3', '--enable-special-filenames', '--', '-&4', '-&5'], {stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe', 'pipe']});
		gpg_verify.stdio[3].on('data', d => status.push(d));
		gpg_verify.stdio[3].on('end', () => {
			accepted(status.join('').toString('utf-8'));
		});

		gpg_verify.stdio[4].write(signature);
		gpg_verify.stdio[4].end();
		gpg_verify.stdio[5].write(commit_msg);
		gpg_verify.stdio[5].end();

		gpg_verify.on('error', (err) => {
			console.error('Got an error', err);
			rejected(err);
		});
	});
}

function ValidateSignatures(sigs) {
	// sort results by keyid and make sure that
	// we have at-least one keyring validate each signature
	const sig_results = {valid: true};
	for (let i=0; i<sigs.length; i++) {
		if (i<sigs.length-1 && sigs[i]["results"].length !== sigs[i+1]["results"].length) {
			throw "Number of signatures different in different keyrings";
		}

		const keyring = sigs[i]["keyring"];
		const results = sigs[i]["results"];

		for (let sig_idx=0; sig_idx<results.length; sig_idx++) {
			const sig = results[sig_idx];
			const keyid = sig["keyid"];

			if (!Object.hasOwn(sig_results, keyid)) {
				sig_results[keyid] = sig;
				sig_results[keyid]["keyring"] = [];
			}

			if (sig.is_missing)
				continue;

			if (!sig.is_valid) {
				sig_results[keyid].is_valid = false;
				sig_results.valid = false;
			}
			if (sig_results[keyid].is_missing) {
				sig_results[keyid].is_missing = false;
				sig_results[keyid].is_valid = sig.is_valid;
			}
			sig_results[keyid]["keyring"].push(keyring);
		}
	}

	return sig_results;
}

Promise.all([ReadKeyringConfig(), ParseCommit('HEAD')])
.then((values) => {
	const keyring_config = values[0];
	const [raw_commit, headers] = values[1];

	const signatures = Object.keys(keyring_config)
	.map(k => {
		const keyring = keyring_config[k];
		keyring['id'] = k;

		return CheckSignatures(keyring, raw_commit, headers)
		.then(ParseSigResults)
		.then(res => {return {keyring: keyring, results: res}});
	}).flat();
	return Promise.all(signatures).then(sigs => {
		headers['signatures'] = ValidateSignatures(sigs);
		return headers;
	})
})
.then(sigs => console.log(JSON.stringify(sigs, undefined, 4)))
.catch(err => {
	console.error('Failure: ', err);
	process.exit(1);
});
