import { spawn } from 'node:child_process'
import { GpgSigIndexes } from './commit.mjs'

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

function CheckSignatures(keyring, raw_commit, headers) {
	const commit_msg = raw_commit.slice(0, headers[GpgSigIndexes][0]) + raw_commit.slice(headers[GpgSigIndexes][1]+1);
	const signature = headers.gpgsig;

	if (!signature) {
		return Promise.resolve('');
	}

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
	const sig_results = {};
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
			}
			if (sig_results[keyid].is_missing) {
				sig_results[keyid].is_missing = false;
				sig_results[keyid].is_valid = sig.is_valid;
			}
			sig_results[keyid]["keyring"].push(keyring);
		}
	}

	// no signatures, so can't be valid commit
	const keyids = Object.keys(sig_results);
	let is_valid = undefined;
	keyids.forEach(keyid => {
		if (sig_results[keyid].is_missing)
			return;
		if (!sig_results[keyid].is_valid)
			is_valid = false;
		else if (is_valid === undefined)
			is_valid = true;
	})
	sig_results.valid = is_valid;

	return sig_results;
}


export {
	CheckSignatures,
	ParseSigResults,
	ValidateSignatures
}