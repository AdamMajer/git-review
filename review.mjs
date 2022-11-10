#!/usr/bin/node

import { readFile } from 'node:fs/promises'
import { argv } from 'node:process';
import { GpgSigIndexes, ParseCommit } from './commit.mjs';
import { CheckSignatures, ParseSigResults, ValidateSignatures } from './gpg_signatures.mjs';


function ReadKeyringConfig() {
	const filename = 'keyrings.json';

	return readFile(filename, {encoding: 'utf-8'})
		.then(json_str => JSON.parse(json_str));
}

const hash = argv.length > 2 ? argv[2] : 'HEAD';

Promise.all([ReadKeyringConfig(), ParseCommit(hash)])
.then((values) => {
	const keyring_config = values[0];
	const [raw_commit, headers] = values[1];

	const signatures = Object.keys(keyring_config)
	.map(k => {
		const keyring = keyring_config[k];
		keyring['id'] = k;

		return CheckSignatures(keyring, raw_commit, headers)
		.then(sig_checks => ParseSigResults(sig_checks))
		.then(res => {return {keyring: keyring, results: res}});
	}).flat();
	return Promise.all(signatures).then(sigs => {
		headers['signatures'] = ValidateSignatures(sigs);
		return headers;
	})
})
.then(sigs => console.log(sigs)) //JSON.stringify(sigs, undefined, 4)))
.catch(err => {
	console.error('Failure: ', err);
	process.exit(1);
});
