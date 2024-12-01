# Polygon zkEVM Series 3: ROM-Induced Unprovable Transactions

## Defination

The ROM-induced unprovable transaction vulnerability in zk systems occurs when the ROM lacks checks for zkCounter or an execution path in the ROM contains unsolvable constraints.

## Exploitation Scenario

Since the state transition of such transaction is unprovable, the attacker can force the transaction to be finalized on L1 through a forced batch. Therefore, the L2 blockchain will be stuck.

## Case 1: Missing Mem-Align counter check 

The Mem-Align counter checks are missing in the opcode CALLDATACOPY. Specifically, there is only a Mem-Align counter check at the start of the label `opCALLDATACOPY` as shown below.

```zkasm
%MAX_CNT_MEM_ALIGN - CNT_MEM_ALIGN - 2   :JMPN(outOfCountersMemalign)
```

However, during the execution of the CALLDATACOPY opcode, the Mem-Align secondary state machine is used twice every time a 32-byte data is copied, but the the Mem-Align counter is not checked dynamically here.

In the CODECOPY opcode, the Mem-Align counter is checked as follows.

```zkasm
opCODECOPYloopInit:
    ; checks zk-counters
    %MAX_CNT_MEM_ALIGN - CNT_MEM_ALIGN  - E     :JMPN(outOfCountersMemalign)
```

Unfortunately, this check is missing in the CALLDATACOPY opcode.

As a consequence, an attacker can construct a transaction that will use more than the maximum Mem-Align counter during execution. Next, the attacker can force this transaction to be finalized on L1 through a forced batch. However, since the Mem-Align counter consumed by this transaction exceeds the upper limit, its state transition cannot be proved by the prover. Therefore, the L2 blockchain will be stuck.

## Case 2: Incorrect implementation of long division

The modexp precompile contract is implemented in the Etrog update of Polygon zkEVM. The `/modexp/array_lib/array_div_long.zkasm` file implements the long division used in this precompile contract. However, the logic of the long division implemented in this file is incorrect. The erroneous logic is located in the following code snippet. Specifically, this code does not work when the remainder is 0 (i.e., when inA is divisible by inB).

```zkasm
array_div_long_mul_quo_inB:
                        :CALL(array_mul)

        $ => D          :MLOAD(array_div_long_len_inB)
        %MAX_CNT_BINARY - CNT_BINARY - 1                                        :JMPN(outOfCountersBinary)
        %MAX_CNT_STEPS - STEP        - 8 - 3*%ARRAY_MAX_LEN - 3*D - 1           :JMPN(outOfCountersStep)

        ; Check the remainder
        $0{receiveLenRemainder()} => D

        ; 1] The received length must be between 1 and %ARRAY_MAX_LEN
        D - 1 => E              :JMPN(failAssert) ; If D = 0, then fail
        %ARRAY_MAX_LEN - D      :JMPN(failAssert) ; If D > %ARRAY_MAX_LEN, then fail
        ; From here, 1 <= D <= %ARRAY_MAX_LEN

        ; 2] To avoid non-determinism, we must ensure that the remainder is trimmed
        ; i.e., that its last chunk is not 0
        ${receiveRemainderChunk(E)} => A
        0 => B
        0               :EQ
        ; From here, the remainder is trimmed

        ; 3] Finally, we must ensure that the remainder is lower than inB
        $ => C           :MLOAD(array_div_long_len_inB)
        C - 1 => RR
        D - 1 => E

        ; save the first non-zero chunk of rem
        A               :MSTORE(array_compare_inB + E)
        E - 1 => E      :JMPN(array_div_long_compare_inB2)
```

Firstly, the following code ensures that the length of the remainder is greater than or equal to 1.

```zkasm
; Check the remainder
$0{receiveLenRemainder()} => D

; 1] The received length must be between 1 and %ARRAY_MAX_LEN
D - 1 => E              :JMPN(failAssert) ; If D = 0, then fail
%ARRAY_MAX_LEN - D      :JMPN(failAssert) ; If D > %ARRAY_MAX_LEN, then fail
; From here, 1 <= D <= %ARRAY_MAX_LEN
```

Secondly, the code below ensures that the last chunk of the remainder is not 0.

```zkasm
 ; i.e., that its last chunk is not 0
${receiveRemainderChunk(E)} => A
0 => B
0               :EQ
```

When the remainder is 0, the above two conditions cannot be met simultaneously, therefore, the state transition of this transaction cannot be proven!


## Case 3: Incorrect array size in the modexp precompile

The `/modexp/array_lib/array_div_long.zkasm` file implements the long division used in the modexp precompile contract. The following code is used to copy data of length `array_mul_len_out` from `array_mul_out` to `array_add_AGTB_inA`.

```zkasm
array_div_long_compare2:
                        :CALL(array_compare)

        %MAX_CNT_STEPS - STEP - 5 - 3*%ARRAY_MAX_LEN - 4*%ARRAY_MAX_LEN - 1        :JMPN(outOfCountersStep)

        2               :MLOAD(array_compare_result)

        D               :MSTORE(array_div_long_len_rem)

        ; prepare output and remainder to be added
        $ => C          :MLOAD(array_mul_len_out)
        C - 1 => RR
        D - 1 => E

array_div_long_res_to_add:
        $ => A          :MLOAD(array_mul_out + RR)
        A               :MSTORE(array_add_AGTB_inA + RR)
        RR - 1 => RR    :JMPN(array_div_long_rem_to_add, array_div_long_res_to_add)
```


However, as shown in the following code, the maximum length of array `array_mul_out` is `%ARRAY_MAX_LEN_DOUBLED` and the maximum length of array `array_add_AGTB_inA` is `%ARRAY_MAX_LEN`.

```zkasm
VAR GLOBAL array_mul_out[%ARRAY_MAX_LEN_DOUBLED]
```

```zkasm
VAR GLOBAL array_add_AGTB_inA[%ARRAY_MAX_LEN]
```

Therefore, when the length of array `array_mul_out` is greater than `%ARRAY_MAX_LEN`, the above code will cause overflow when copying data. The overflow issue will cause the following PIL constraints cannot be satisfied which can lead to an unprovable transaction.

```zkasm
1               :MLOAD(array_compare_result)
```

## Case 4: Missing checks in ChangeL2Block transaction

Polygon zkEVM introduced a new transaction type, ChangeL2Block, in the Etrog update, with the format as follows. The `indexL1InfoTree` variable is used to specify the path for the SMT proof.

```
;; ChangeL2BlockTx:
;;   - fields: [type | deltaTimestamp | indexL1InfoTree ]
;;   - bytes:  [  1  |       4        |        4        ]
```

In the file `process-change-l2-block.zkasm`, the following code is used to verify the SMT proof. The path of the SMT proof is `indexL1InfoTree`, and the leaf value is `Keccak256(gerL1InfoTree||blockHashL1||timestamp)`.

```zkasm
$                                                   :MLOAD(indexL1InfoTree), JMPZ(skipSetGERL1InfoTree)

${getL1InfoGER(mem.indexL1InfoTree)} => A           :MSTORE(gerL1InfoTree)
${getL1InfoBlockHash(mem.indexL1InfoTree)} => B     :MSTORE(blockHashL1InfoTree)
${getL1InfoTimestamp(mem.indexL1InfoTree)} => C     :MSTORE(timestampL1InfoTree)
                                                    :CALL(verifyMerkleProof)
```

The SMT is maintained by the L1 contract `DepositContractBase.sol`. From the `getRoot` function, we know that the path of the SMT proof is `depositCount`.

```solidity
function getRoot() public view virtual returns (bytes32) {
        bytes32 node;
        uint256 size = depositCount;
        bytes32 currentZeroHashHeight = 0;

        for (
            uint256 height = 0;
            height < _DEPOSIT_CONTRACT_TREE_DEPTH;
            height++
        ) {
            if (((size >> height) & 1) == 1)
                node = keccak256(abi.encodePacked(_branch[height], node));
            else
                node = keccak256(abi.encodePacked(node, currentZeroHashHeight));

            currentZeroHashHeight = keccak256(
                abi.encodePacked(currentZeroHashHeight, currentZeroHashHeight)
            );
        }
        return node;
}
```

Therefore, if a malicious sequencer set the `indexL1InfoTree` variable in the `ChangeL2Block` transaction to a very large number (much larger than the depositCount), the state transition of this batch will be unprovable. This is because the leaf value of such path is zero but `Keccak256(gerL1InfoTree||blockHashL1||timestamp)` cannot be zero!


## Disclose Timeline
- **Case 1**: Reported in <span style="color:blue;">August 2023</span> and confirmed as <span style="color:red;">high severity</span>.  
- **Case 2**: Reported in <span style="color:blue;">February 2024</span> and confirmed as <span style="color:red;">medium severity</span>.  
- **Case 3**: Reported in <span style="color:blue;">February 2024</span> and acknowledged as internally known.
- **Case 4**: Reported in <span style="color:blue;">February 2024</span> and confirmed as <span style="color:red;">medium severity</span>.  



