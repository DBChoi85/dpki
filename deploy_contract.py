#!/usr/bin/env python3
import json, os
from pathlib import Path
from web3 import Web3
from solcx import compile_standard, install_solc, set_solc_version

RPC=os.getenv("BESU_RPC_URL")
if not RPC:
    raise SystemExit("BESU_RPC_URL required (Besu JSON-RPC endpoint)")
SOLC="0.8.24"
CONTRACT=Path("contracts/DPKICommitmentRegistry.sol")
ARTIFACT=Path("build/DPKICommitmentRegistry.json")
owner_pk=os.getenv("BESU_PRIVATE_KEY")
validator_pk=os.getenv("BESU_VALIDATOR_PRIVATE_KEY")
if not owner_pk: raise SystemExit("BESU_PRIVATE_KEY required (owner/updater account)")
if not validator_pk: raise SystemExit("BESU_VALIDATOR_PRIVATE_KEY required (independent validator account)")

w3=Web3(Web3.HTTPProvider(RPC,request_kwargs={"timeout":120}))
chain_id=w3.eth.chain_id
owner=w3.eth.account.from_key(owner_pk)
validator=w3.eth.account.from_key(validator_pk)
if owner.address.lower()==validator.address.lower():
    raise SystemExit("Updater and validator must use different Besu accounts")

try: set_solc_version(SOLC)
except Exception:
    install_solc(SOLC); set_solc_version(SOLC)

compiled=compile_standard({
 "language":"Solidity",
 "sources":{"DPKICommitmentRegistry.sol":{"content":CONTRACT.read_text()}},
 "settings":{"optimizer":{"enabled":True,"runs":200},"evmVersion":"paris",
 "outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}
})
c=compiled["contracts"]["DPKICommitmentRegistry.sol"]["DPKICommitmentRegistry"]
factory=w3.eth.contract(abi=c["abi"],bytecode=c["evm"]["bytecode"]["object"])
tx=factory.constructor().build_transaction({
 "from":owner.address,"nonce":w3.eth.get_transaction_count(owner.address,"pending"),
 "chainId":chain_id,"gasPrice":0
})
tx["gas"]=int(w3.eth.estimate_gas(tx)*1.2)
signed=owner.sign_transaction(tx)
txh=w3.eth.send_raw_transaction(signed.raw_transaction)
receipt=w3.eth.wait_for_transaction_receipt(txh,timeout=120)
if receipt.status!=1: raise RuntimeError("deployment failed")

contract=w3.eth.contract(address=receipt.contractAddress,abi=c["abi"])
auth_tx=contract.functions.setValidator(validator.address,True).build_transaction({
 "from":owner.address,"nonce":w3.eth.get_transaction_count(owner.address,"pending"),
 "chainId":chain_id,"gasPrice":0
})
auth_tx["gas"]=int(w3.eth.estimate_gas(auth_tx)*1.2)
signed_auth=owner.sign_transaction(auth_tx)
auth_h=w3.eth.send_raw_transaction(signed_auth.raw_transaction)
auth_receipt=w3.eth.wait_for_transaction_receipt(auth_h,timeout=120)
if auth_receipt.status!=1: raise RuntimeError("validator authorization failed")

ARTIFACT.parent.mkdir(exist_ok=True)
ARTIFACT.write_text(json.dumps({"address":receipt.contractAddress,"abi":c["abi"],
 "chainId":chain_id,"deploymentTx":txh.hex(),"validatorAuthorizationTx":auth_h.hex(),
 "updater":owner.address,"validator":validator.address},indent=2))
print("DEPLOYMENT SUCCESS")
print("Contract  :",receipt.contractAddress)
print("Updater   :",owner.address)
print("Validator :",validator.address)
print("Artifact  :",ARTIFACT)
