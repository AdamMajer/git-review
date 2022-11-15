#!/usr/bin/node

import { spawn } from 'node:child_process';
import { argv } from 'node:process'
import { CommitCommit, ParseCommit, SignedData } from "./commit.mjs";
import { DearmorSignature, EnarmorSignature } from './gpg_signatures.mjs';

if (argv.length < 3) {
	console.log(' Syntax:  sign.mjs   keyid   [sha]');
	process.exit(0);
}

const gpg_executable = '/usr/bin/gpg';

const commit_sha = argv.length > 3 ? argv[3] : 'HEAD';
const keyid = argv[2];


function MergeSignatures(commit, signature) {
	const sig = commit['gpgsig'];

	if (sig === undefined) {
		return EnarmorSignature(signature);
	}

	const combined_signature = Buffer.concat([DearmorSignature(sig), signature]);
	return EnarmorSignature(combined_signature);
}

function SignCommit(commit) {
	return new Promise((accepted, rejected) => {
		const params = ['--batch', '--detach-sign', '--default-key', keyid, '--status-fd', '3', '--enable-special-filenames', '-o', '-&5', '--', '-&4'];
		const signproc = spawn(gpg_executable, params, {stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe', 'pipe']})

		const sig = [];
		signproc.stdio[5].on('data', d => sig.push(d));
		signproc.stdio[4].end(commit[SignedData]);
		signproc.on('exit', (res) => {
			if (res !== 0) {
				rejected('signer ended error: ' + res);
				return;
			}

			try {
				commit['gpgsig'] = MergeSignatures(commit, Buffer.concat(sig));
				accepted(commit);
			}
			catch (err) {
				rejected ('Merging signatures failed with error: ' + err);
			}
		})
	});
}

ParseCommit(commit_sha)
.then(commit => SignCommit(commit))
.then(commit => CommitCommit(commit))
.then (r => console.log(r))
.catch(err => {
	console.error(err);
})
