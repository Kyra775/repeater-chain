# Tokenomics of Repeater Chain

Repeater Chain introduces a native token, **$ECHO**, to incentivize validators and maintain economic balance.

---

## Token Details

| Component               | Description                            |
|-------------------------|----------------------------------------|
| **Token Name**          | ECHO                                  |
| **Max Supply**          | 100 million                          |
| **Validator Reward**    | Fixed + Penalty-based:                |
|                         | reward = base + (tx_count * 0.001 ECHO)|
| **Burn Mechanism**      | Invalid transactions → 10% token burn |
| **Validator Staking**   | Minimum 1,000 ECHO per validator       |

---

## Economic Principles

1. **Reward System**:
   Validators are rewarded for participating in the network:
   - Base reward is fixed for each block.
   - Additional reward scales with the number of transactions validated.

2. **Penalty and Burn Mechanism**:
   - If a validator submits an invalid transaction, 10% of their staked tokens are burned.

3. **Staking Requirement**:
   - To become a validator, a node must stake at least 1,000 ECHO tokens.
   - This ensures validators have a vested interest in the security of the network.

4. **Supply Cap**:
   - The total supply of ECHO is fixed at 100 million tokens to ensure scarcity.