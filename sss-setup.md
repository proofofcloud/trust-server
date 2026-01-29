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

Bash
sss-tool initialize --moniker "<your_participant_name>"
Example: sss-tool initialize --moniker "scrt_labs"

Output: Generates a local configuration (likely config.toml or similar) and identity files.

### 2. Generate DKG Commitments (Round 1)
Participants generate their initial commitments for the Distributed Key Generation (DKG) process.

Bash
 <t> is the threshold M
<n> is the total number of participants N
sss-tool dkg-round1 --threshold <t> --participants <n>
Output: Generates a Commitment file/string.

Action: Share this commitment with all other participants.

### 3. Generate Shares (Round 2)
Once you have received commitments from all other participants, use them to generate the private shares.

Bash
# This command typically takes the list of commitments from peers
sss-tool dkg-round2 --commitments <path_to_commitments_file_or_list>
Output:

trustserver_public_key.pub: The collective public key.

Encrypted Shares: Files specifically encrypted for each peer.

Action: Send the respective Encrypted Share to each corresponding participant.

### 4. Finalize and Save Share (Round 3)
After receiving the encrypted shares from all other participants, import them to finalize your secret share.

Bash
sss-tool dkg-finalize --shares <path_to_received_shares>
Output: trustserver_share.json (or .key)

CRITICAL: This file is your unique private share.

Backup: Store it securely offline.

Install: Place it in the config directory of your Trust-Server installation.

5. Publish Public Information
To complete the setup, public artifacts must be committed to the repository:

Public Key: Copy the contents of the public key file to: https://github.com/proofofcloud/trust-server/blob/main/public_info/public_key.txt

Peers List: Update the list of available peers at: https://github.com/proofofcloud/trust-server/blob/main/public_info/peers_list.txt

Phase 2: Adding a New Participant
Adding a new participant requires a quorum of at least M existing participants to sign off on the addition.

Step 1: New Participant Setup
The new participant initializes and generates a request to join.

Bash
sss-tool initialize --moniker "<new_participant_name>"
sss-tool join-request
Output: A "Join Request" (containing an ephemeral public key).

Action: Send the Join Request to the existing group.

Step 2: Quorum Approval (Existing Participants)
At least M existing participants must approve the new member.

Bash
sss-tool approve-participant \
  --request <path_to_join_request> \
  --share <path_to_my_private_share>
Output: A "Partial Approval" or "Reshare" fragment.

Action: Send this fragment to the new participant.

Step 3: Finalize New Participant
The new participant collects the approvals to construct their key share.

Bash
sss-tool finalize-join --approvals <list_of_approval_files>
Output: trustserver_share.key

Action: Securely back up this key.
