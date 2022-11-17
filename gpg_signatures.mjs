import { spawn } from 'node:child_process'
import { SignedData } from './commit.mjs'

// see rfc4880 §6
function DearmorSignature(signature) {
	const lines = signature.split('\n');

	const start = lines[0];
	const end = lines[lines.length - 1];

	if (start.replace('BEGIN', 'END') !== end)
		throw "Invalid PGP signature";

	// remove the start and end of the signature
	lines.pop();
	lines.shift();

	// remove the headers
	while (lines[0].length > 0)
		lines.shift();
	lines.shift();

	// remove checksum on the last line
	if (lines[lines.length-1].startsWith('='))
		lines.pop();

	// remaining is a base64 encoded PGP signature
	return Buffer.from(lines.join(''), 'base64');
}

// see rfc4880 §6
function SignatureCRC(sig)
{
	const CRC24_INIT = 0xB704CE;
	const CRC24_POLY = 0x1864CFB;

	let crc = CRC24_INIT;
	for (let pos=0; pos<sig.length; pos++) {

		crc ^= sig.at(pos) << 16;
		for (let i = 0; i < 8; i++) {
			crc <<= 1;
			if (crc & 0x1000000)
				crc ^= CRC24_POLY;
		}

		crc &= 0xFFFFFF;
	}

	return Buffer.from([crc >> 16, (crc >> 8) & 0xFF, crc & 0xFF])
}

// see rfc4880 §6
function EnarmorSignature(signature) {
	const encoded = signature.toString('base64');
	const lines = [];
	for (let i=0; i<encoded.length; i+=64)
		lines.push(encoded.slice(i, i+64));

	return '-----BEGIN PGP SIGNATURE-----\n\n' +
		lines.join('\n') + '\n' +
		'=' + SignatureCRC(signature).toString('base64') + '\n' +
		'-----END PGP SIGNATURE-----';
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

function ListSignatures(headers) {
	const signature = headers.gpgsig;

	return new Promise((accepted, rejected) => {
		const gpg_verify = spawn('gpgv2', ['--keyring', '/dev/null', '--status-fd', '3', '--enable-special-filenames', '--', '-&4', '/dev/null'], {stdio: ['ignore', 'ignore', 'inherit', 'pipe', 'pipe']});
		let status = [];

		console.log(signature);
		gpg_verify.stdio[3].on('data', d => status.push(d));
		gpg_verify.stdio[4].end(signature);

		gpg_verify.on('error', (code) => {
			if (code == 0) {
				accepted(status.join('').toString('utf-8'));
				return;
			}

			console.error('gpgv2 returned status:', err);
			rejected('ListSignatures error code ' + err);
		})
		gpg_verify.on('error', (err) => {
			console.error('Got an error', err);
		});
	})
	.then ((result_string) => ParseSigResults(result_string))
	.then (data => {
		return data
		.map(res => {
			if (Object.hasOwn(res, 'keyid') && Object.hasOwn(res, 'timestamp'))
				return { "keyid": res.keyid, "timestamp": res.timestamp };
			return undefined;
		})
		.filter(obj => obj !== undefined);
	});
}

function CheckSignatures(keyring, commit) {
	const signature = commit['gpgsig'];

	if (!signature) {
		return Promise.resolve('');
	}

	return new Promise((accepted, rejected) => {
		let status = [];

		const params = ['--keyring', keyring.filename, '--status-fd', '3', '--enable-special-filenames', '--', '-&4', '-&5'];
		const gpg_verify = spawn('gpgv2', params, {stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe', 'pipe']});
		gpg_verify.stdio[3].on('data', d => status.push(d));
		gpg_verify.stdio[4].end(signature);
		gpg_verify.stdio[5].end(commit[SignedData]);

		gpg_verify.on('exit', (code) => {
			accepted(status.join('').toString('utf-8'));
		})
		gpg_verify.on('error', (error) => {
			rejected(error);
		})
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
	DearmorSignature,
	EnarmorSignature,
	CheckSignatures,
	ListSignatures,
	ParseSigResults,
	ValidateSignatures
}
