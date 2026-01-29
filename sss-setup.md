# Trust-Server Shamir Secret Sharing MPC Setup Guide

This document describes the Multi-Party Computation (MPC) setup process for the Trust-Server project. This protocol allows a group of N actors to generate a distributed private key where a threshold of M participants is required to perform operations.

Repository: https://github.com/proofofcloud/trust-server

## Prerequisites
Executable: Ensure the sss-tool binary is built and available in your system path.

Secure Environment: Run all commands that generate private material in a secure, isolated environment.

## Phase 1: Genesis Setup (Initial Ceremony)
This phase establishes the initial group of N participants and the threshold M.

### 1. Initialize Participant
Every participant must first initialize their local environment and identity.

```
sss-tool initialize --moniker "<your_participant_name>"

# Example:
sss-tool initialize --moniker "scrt_labs"

```

Output: Generates a local configuration file `private.sss`.

### 2. Generate DKG Commitments (Round 1)
Participants generate their initial commitments for the Distributed Key Generation (DKG) process.

```
<m> is the threshold, i.e. the quorum size that will be able to reconstruct the full key
sss-tool initial-pub-data --m <m>

# Example:
sss-tool initial-pub-data --m 3

# output:
{"alice":{"pub_coeffs":["d2KrWUHLSOMA2NueXt8kLNiy7c6s2y2oSmGPMRnilBA=","LFdaFEP/zXG7a+4UO7/e1O7Rf2s4REkjMiFlJsKUOVY=","hcVbw+HnrzmSEIjbunKVskILzV6DwCz48vecyjfZvfc="],"pops":["+ITsY7oKPDcn34Ttsg0G2JX+OK69R2j6pI8/Wd7Edw5up3QfmGS9vk3dwnzh5p3XEsxMJAEEIgCuYA+bb9xeDA==","73gyloapp9KPSKZcPayOVT7kNRNiFMMsg1EVzdXqQFcIthcw9W7um4pJjN3a8U0oZwKgvJ3ZFWzbqwHiiPv+CA==","KucX3lvCMwmX0wsBmsvZE/uaHO1DWVfcKV9hXL2c27f0SYJSuvqQ+NteEsLpiSV+nYkleIjczUFz1f1kdAcFBQ=="]}}
```
Output: Generates a Commitment json.

Action: Share this commitment with all other participants. Once all N participants generated and shared their DKG commitments, they all should be united into a single json.
Like this:
```
{"alice":{ ... }, "bob":{ ... }, ... }
```

### 3. Import all DKG Commitments and Generate encrypted partial Shares (Round 2)

```
sss-tool init-common --pub-datas '{...}'

# where '{...}' is the json that contains all the initial commitments (as described in the previous step).
```

Output: Generates a local configuration file `shares.sss`, and prints the json with encrypted partial shares to all other participants. Example:
```
{"alice":{"bob": "xxxx", "charlie": "xxxxx", ...}}
```

Action: Share this output with all other participants. Once all N participants generated and shared their partial shares, they all should be united into a single json. Like this:|
```
{"alice":{"bob": "xxxx", "charlie": "xxxxx", ...}, "bob":{"alice": "xxxx", ....}, "charlie": {...}, ...}
```

### 4. Finalize and Save Share (Round 3)
After creating the unified json of all partial shares

```
sss-tool init-my-share --shares pub-datas '{...}' --partial-shares '{...}'
```

Output: Updates the local `private.sss` file. Decodes, verifies and saves the imported share.

**CRITICAL**: This file is your unique private share.
Backup: Store it securely offline.

### 5. Publish Public Information
```
sss-tool info
```

This should print the initialization status. Output should be like this:
```
Moniker: alice
Initialization ceremony complete.
M = 2
Shared Pubkey = 3c855110850b4e303e640b0c3c06bedd5b6d3b3526b46f7a0ef10ab2e8c38aaa
My share initialized
```

The share Pubkey should be published.
Peers List: Update the list of available peers at: https://github.com/proofofcloud/trust-server/blob/main/public_info/peers_list.txt

