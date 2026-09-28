#!/usr/bin/env python3
import argparse, json, os, sys
from eth_account import Account
from web3 import Web3

def load_abi(path):
    artifact=json.loads(open(path, encoding='utf-8').read())
    return artifact['abi']

def send_transaction(w3, fn, account):
    tx=fn.build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address, 'pending'),
        'chainId': w3.eth.chain_id,
        'gas': 500000,
        'gasPrice': 0,
    })
    signed=account.sign_transaction(tx)
    txh=w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(txh, timeout=120)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--rpc', default=os.getenv('BESU_RPC_URL'), help='Besu JSON-RPC endpoint (or set BESU_RPC_URL)')
    ap.add_argument('--contract', required=True)
    ap.add_argument('--artifact', default='build/DPKICommitmentRegistry.json')
    ap.add_argument('--domain', default='negative-test-domain')
    args=ap.parse_args()
    if not args.rpc:
        raise SystemExit("Besu JSON-RPC endpoint required: use --rpc or BESU_RPC_URL")

    updater_key=os.getenv('BESU_PRIVATE_KEY')
    validator_key=os.getenv('BESU_VALIDATOR_PRIVATE_KEY')
    if not updater_key: sys.exit('BESU_PRIVATE_KEY required')
    if not validator_key: sys.exit('BESU_VALIDATOR_PRIVATE_KEY required')

    updater=Account.from_key(updater_key)
    validator=Account.from_key(validator_key)
    if updater.address.lower()==validator.address.lower():
        sys.exit('Updater and validator must use different accounts')

    w3=Web3(Web3.HTTPProvider(args.rpc, request_kwargs={'timeout':120}))
    if not w3.is_connected(): sys.exit(f'Cannot connect to Besu RPC: {args.rpc}')
    contract=w3.eth.contract(address=Web3.to_checksum_address(args.contract), abi=load_abi(args.artifact))
    domain_id=Web3.keccak(text=args.domain)
    proposed_root=Web3.keccak(text='DPKI-NEGATIVE-TEST-PROPOSED-ROOT')
    mismatching_root=Web3.keccak(text='DPKI-NEGATIVE-TEST-MISMATCHING-ROOT')

    before=contract.functions.getCommitment(domain_id).call()

    # Make the negative test repeatable. A prior expected mismatch leaves the
    # proposal pending because the reverting validation transaction cannot
    # delete state created by the earlier proposal transaction.
    pending=contract.functions.getPendingCommitment(domain_id).call()
    if pending[4]:
        pending_updater=pending[3]
        print(f'Existing pending proposal detected for {args.domain}')
        print(f'  pending updater : {pending_updater}')
        if pending_updater.lower()!=updater.address.lower():
            sys.exit('FAIL: pending proposal belongs to a different updater; use another domain or clear it with that updater')
        cleanup=send_transaction(w3, contract.functions.cancelPendingCommitment(domain_id), updater)
        if cleanup.status != 1:
            sys.exit('FAIL: could not clear existing pending proposal')
        print('  cleanup         : SUCCESS')

    proposal=send_transaction(w3, contract.functions.proposeCommitment(domain_id, proposed_root,100,5), updater)
    if proposal.status != 1:
        pending=contract.functions.getPendingCommitment(domain_id).call()
        sys.exit(f'FAIL: proposeCommitment transaction failed; pending_exists={pending[4]}, pending_updater={pending[3]}')

    rejected=False
    try:
        receipt=send_transaction(w3, contract.functions.validateAndCommit(domain_id,mismatching_root), validator)
        rejected=(receipt.status==0)
    except Exception:
        rejected=True

    after=contract.functions.getCommitment(domain_id).call()
    unchanged=tuple(before)==tuple(after)

    # The expected validation revert leaves C_D pending. Clean it up so the
    # same negative test can be executed repeatedly with the same domain.
    pending=contract.functions.getPendingCommitment(domain_id).call()
    cleanup_ok=True
    if pending[4]:
        cleanup=send_transaction(w3, contract.functions.cancelPendingCommitment(domain_id), updater)
        cleanup_ok=(cleanup.status==1)

    print(f'Mismatch rejected       : {rejected}')
    print(f'Anchored state unchanged: {unchanged}')
    print(f'Pending state cleaned   : {cleanup_ok}')
    if rejected and unchanged and cleanup_ok:
        print('PASS')
        return 0
    print('FAIL')
    return 1

if __name__=='__main__':
    raise SystemExit(main())
