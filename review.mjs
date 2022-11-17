#!/usr/bin/node

import { readFile } from 'node:fs/promises'
import { argv } from 'node:process';
import { ParseCommit } from './commit.mjs';
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
	const commit = values[1];

	const signatures = Promise.all(
		Object.keys(keyring_config)
		.map(k => {
			const keyring = keyring_config[k];
			keyring['id'] = k;

			return CheckSignatures(keyring, commit)
			.then(sig_checks => ParseSigResults(sig_checks))
			.then(res => {return {keyring: keyring, results: res}})
			.catch(error => {
				console.error(error);
				return {keyring: keyring, results: undefined};
			});
		})
	).then(sigs => {
		commit['signatures'] = ValidateSignatures(sigs);
		return commit;
	});

	return signatures;
})
.then(sigs => console.log(sigs)) //JSON.stringify(sigs, undefined, 4)))
.catch(err => {
	console.error('Failure: ', err);
	process.exit(1);
});
