# Polygon zkEVM Series 1: Dual Execution Path Vulnerabilities

## Defination

A dual execution path vulnerability is fundamentally a soundness vulnerability. In the context of a zkEVM written in zkasm, such a vulnerability arises when multiple execution paths can lead to the same final state but consume different zk-related resources (e.g., STEP counters).


## Exploitation Scenario

Here’s how an attacker can exploit a dual execution path vulnerability in zkEVM:
1.	**Crafting an Ambiguous Transaction**:
Design a transaction such that its execution can follow two different execution traces to reach the same state.

2.	**Valid Proof Generation**:
Under one branch, generate a proof for the transaction, consuming related-fewer STEP counters and reach valid state transition.

3.	**Forgery Proof Generation**:
Under another branch, generate a proof for the transaction, consuming more STEP counters and causing an out-of-counter error.
	
4.	**Implications**:
The transactions are both provable and can be used to disrupt system integrity by proving a valid execution to trigger an error.
This opens the door to attacks such as double-spending.



## Case 1 in Elliptic Curve Calculations

The following code snippet in the file `mulPointEc.zkasm` is used for elliptic curve calculations:

```zkasm
mulPointEc:
    RR      :MSTORE(mulPointEc_RR)
    HASHPOS :MSTORE(mulPointEc_HASHPOS)

    256 => RCX

    ; HASHPOS used to mulPointEc_p3_no_infinity
    0n => HASHPOS :MSTORE(mulPointEc_p3_x)

    0n      :MSTORE(mulPointEc_p3_y)

    $ => A  :MLOAD(mulPointEc_p1_x)
    $ => B  :MLOAD(mulPointEc_p1_y)
    $ => C  :MLOAD(mulPointEc_p2_x)
    $ => D  :MLOAD(mulPointEc_p2_y)

    ; check p1.x == p2.x
    ${A == C}     :JMPZ(mulPointDiffInitalPoints)
    C             :ASSERT

    ; check p1.y == p2.y
    D => A
    $             :EQ,JMPC(mulPointSameInitalPoints)

    ; p2 == -p1
    1n            :MSTORE(mulPointEc_p12_empty),JMP(mulPointEc_loop)

mulPointSameInitalPoints:
    ; p2 == p1
    0n                        :MSTORE(mulPointEc_p12_empty)
    $ => A                    :MLOAD(mulPointEc_p1_x)
    ${xDblPointEc(A,B)} => E  :MSTORE(mulPointEc_p12_x)
    ${yDblPointEc(A,B)}       :ARITH_ECADD_SAME, MSTORE(mulPointEc_p12_y),JMP(mulPointEc_loop)

mulPointDiffInitalPoints:
    ; p2.x != p1.x ==> p2 != p1
    0n                            :MSTORE(mulPointEc_p12_empty)
    ${xAddPointEc(A,B,C,D)} => E  :MSTORE(mulPointEc_p12_x)
    ${yAddPointEc(A,B,C,D)}       :ARITH_ECADD_DIFFERENT, MSTORE(mulPointEc_p12_y)
```
The key point is the following line:

```zkasm
${A == C}     :JMPZ(mulPointDiffInitalPoints)
```

It can be seen that the execution branch of the program is determined by a free variable.

In the next line, the following code performs a dual path check to ensure that this branch is executed if and only if `A == C`.

```zkasm
C             :ASSERT
```

However, a similar dual path check is missing in the `mulPointDiffInitalPoints` label.
This allows a malicious prover to manipulate the free variable `${A == C}` to bypass normal execution flow, leading to non-deterministic execution.

### Steps to Reproduce

1.	Set p1 and p2 to the same elliptic curve point. This implies `A == C` (i.e., p1.x == p2.x).
2.	Intentionally set the free variable `${A == C}` to 0.
3.	Observe that the program jumps to the `mulPointDiffInitalPoints` label instead of `mulPointSameInitalPoints`.
4.	At `mulPointDiffInitalPoints`, a point addition is executed even though point doubling should have occurred.


### Feasibility Analysis
We know that the following 4 equations are used to verify calculations related to elliptic curves.

```
EQ1: s * x2 - s * x1 - y2 + y1 + (q0 * p) = 0   ;lambda - ADD
EQ2: 2 * s * y1 - 3 * x1 * x1 + (q0 * p) = 0    ;lambda - DBL
EQ3: s * s - x1 - x2 - x3 + (q1 * p) = 0        ;x3
EQ4: s * x1 - s * x3 - y1 - y3 + (q2 * p) = 0   ;y3
```

To be specific, when performing point addition, EQ1, EQ3, and EQ4 are enabled. In contrast, when performing point doubling, EQ2, EQ3, and EQ4 are enabled.

Here, we aim to verify whether the constraints for point addition can be satisfied when p1 and p2 are the same point. Since p1 and p2 are the same points, it means that `x1==x2` and `y1==y2`. As a result, EQ1 can be simplified as `y1=y2`, and there is no constraint to the committed polynomial `s`.

Therefore, we can simply set s equal to `3x1^2/2y1`, and this will produce the same x3 and y3 as the point doubling calculation. Until now, a dual execution path has proven to be feasible.


## Case 2 in Ecrecover Implementation

It is known that the formula of the elliptic curve used by Ethereum is `y^2 = x^3 + 7 mod p`. Moreover, the value `r` in the transaction signature is the x-coordinate of the point P (the point P is dynamically generated when signing the transaction). In the file `ecrecover.zkasm`, the following code derives the y-coordinate of the point P from its x-coordinate.

```zkasm
ecrecover_v_ok:
        ;
        ; y^2 = x^3 + 7
        ;
        ; A*B*A + 7 = calculate y from x
        $ => A,B    :MLOAD(ecrecover_r),CALL(mulFpEc)

        C => A
        $ => B      :MLOAD(ecrecover_r),CALL(mulFpEc)

        7 => A      :CALL(addFpEc)


        C           :MSTORE(ecrecover_y2),CALL(sqrtFpEc)

        ;; If has root y ** (p-1)/2 = 1, if -1 => no root, not valid signature

        %FPEC_NON_SQRT => A
        C => B
        $ => E      :EQ,JMPNC(ecrecover_has_sqrt)

        ; hasn't sqrt, now verify

        $ => C      :MLOAD(ecrecover_y2),CALL(checkSqrtFpEc)
        ; check must return on A register 1, because the root has no solution
        1           :ASSERT,JMP(ecrecover_not_exists_sqrt_of_y)
```

Note that an x-coordinate corresponds to two points on the elliptic curve, and the `v` value in the transaction signature is used to determine which of these two points corresponds to the signer's public key.

As shown below, from the definition of the function `sqrtFpEc`, we know that both the y-coordinates of the two points satisfy the corresponding constraints.

```zkasm
sqrtFpEc:

        C               :MSTORE(sqrtFpC_tmp)

        ; [A] * [A] + 0 = [D] * 2 ** 256 + [E]

        ; set C because if jmp to sqrtFpEc C must have return value (FPEC_NON_SQRT)
        ${var _sqrtFpEc_sqrt = sqrtFpEc(C) } => A,C   :MSTORE(sqrtFpC_res)
        %FPEC_NON_SQRT => B
        $                                             :EQ,JMPC(sqrtFpEc_End)

        A => B
        0 => C

        $${var _sqrtFpEc_sq = _sqrtFpEc_sqrt * _sqrtFpEc_sqrt }

        ${_sqrtFpEc_sq >> 256} => D
        ${_sqrtFpEc_sq} => E :ARITH

        ;
        ; with committed E,D
        ; FpEc * [k] + C = D * 2 ** 256 + E
        ;

        $ => C          :MLOAD(sqrtFpC_tmp)
        ${_sqrtFpEc_sq / const.FPEC} => B
        %FPEC => A
        E :ARITH

        $ => C          :MLOAD(sqrtFpC_res),RETURN

sqrtFpEc_End:
        :RETURN
```

Next, in the file `ecrecover.zkasm`, the following code compares whether the y-coordinate output by the function `sqrtFpEc` matches the correct y-coordinate indicated by the `v` value in the transaction signature. It is matched only when the `v` value and the y-coordinate have the same parity. If they don't match, the inverse of the y-coordinate is used for the remaining calculations.

```zkasm
ecrecover_has_sqrt:
        ; (v == 1b) ecrecover_y_parity = 0x00
        ; (v == 1c) ecrecover_y_parity = 0x01

        ; C,B: y = sqrt(y^2)
        ; check B isn't an alias (B must be in [0, FPEC-1])

        %FPEC_MINUS_ONE => A
        0           :LT         ; assert to validate that B (y) isn't n alias.

        ; C,B: y = sqrtFpEc(y^2)

        0x01n => A
        $ => A      :AND
        $ => B      :MLOAD(ecrecover_v_parity)

        ; ecrevover_y xor ecrecover_y_parity => 0 same parity, 1 different parity
        ; ecrecover_y2  v parity
        ; parity (A)       (B)      A+B-1
        ;      0            0        -1     same parity
        ;      0            1         0     different parity
        ;      1            0         0     different parity
        ;      1            1         1     same parity

        A + B - 1   :JMPNZ(ecrecover_v_y2_same_parity)

        ; calculate neg(ecrecover_y) C = (A:FPEC) - (B:ecrecovery_y)

        %FPEC => A
        C => B
        $ => C      :SUB
```

The key point here is that the function `sqrtFpEc` can output two valid y-coordinates, and if the y-coordinate is not consistent with the `v` value, it is corrected by taking its inverse. This incorrect implementation leads to dual execution paths. In other words, the output of the `sqrtFpEc` function (i.e. the y-coordinate) can be arbitrarily set by the prover, and the program will continue to run regardless of whether the y-coordinate is consistent with the `v` value. That is to say, if the prover makes the `sqrtFpEc` function output different y-coordinates, it will lead to different program execution paths. One path will directly jump to the `ecrecover_v_y2_same_parity` label, while the other will first calculate the inverse of the y-coordinate. Although these two execution paths produce the same computational results, they consume different amounts of the STEP counter. 


## Case 3 in Modexp Precompile

The `/modexp/array_lib/array_div_long.zkasm` file implements the long division used in the modexp precompile contract. However, there exists a dual execution path vulnerability in this file. This file uses the following two pieces of code to verify the correctness of long division.

First, the following code ensures that the remainder is smaller than the divisor.

```zkasm
array_div_long_compare2:
                        :CALL(array_compare)

        %MAX_CNT_STEPS - STEP - 5 - 3*%ARRAY_MAX_LEN - 4*%ARRAY_MAX_LEN - 1        :JMPN(outOfCountersStep)

        2               :MLOAD(array_compare_result)
```

Second, the following code ensures that the quotient multiplied by the divisor plus the remainder equals the dividend.

```zkasm
array_div_long_compare3:
                        :CALL(array_compare)

        %MAX_CNT_STEPS - STEP - 4      :JMPN(outOfCountersStep)

        1               :MLOAD(array_compare_result)
```

These two checks guarantee the correctness of long division.

However, an attacker can still provide malicious data. The key insight to launching the attack is that the provided malicious data consumes a large amount of zkCounter in the process of big integer multiplication, so **an out of counter error occurs before the above two checks are performed**.

For example, an attacker can malicious set the register C to `%ARRAY_MAX_LEN` in the following code.

```zkasm
array_div_long_prepare_mul_quo_inB:
        $0{receiveLenQuotient()} => C

        ; The received length must be between 1 and %ARRAY_MAX_LEN
        C - 1 => RR             :JMPN(failAssert) ; If C = 0, then fail
        %ARRAY_MAX_LEN - C      :JMPN(failAssert) ; If C > %ARRAY_MAX_LEN, then fail
```

Therefore, in the following big integer multiplication logic, about 900 ARITH zkCounter is consumed which is much larger than the original.

```zkasm
array_mul_long:
        %MAX_CNT_ARITH - CNT_ARITH - 1        :JMPN(outOfCountersArith)
        %MAX_CNT_STEPS - STEP      - 9        :JMPN(outOfCountersStep)

        C => A
        D => B
        0 => C,D
        ${A*B} => E :ARITH
        A => C
        B => D
        ; E holds C*D

        %MAX_CNT_BINARY - CNT_BINARY                 - 4*E                :JMPN(outOfCountersBinary)
        %MAX_CNT_ARITH - CNT_ARITH                   - E                  :JMPN(outOfCountersArith)
        %MAX_CNT_STEPS - STEP        - 7 - 2*C - 2*D - 33*E - 2 - 3*C - 1 :JMPN(outOfCountersStep)
```

An attacker can craft a transaction that triggers an out of counter error in the following check after adding an additional 900 ARITH zkCounter.

```zkasm
%MAX_CNT_ARITH - CNT_ARITH                   - E                  :JMPN(outOfCountersArith)
```

In conclusion, an attacker can craft a transaction that can both be proven valid and be proven to trigger an out-of-counter error.


## Disclose Timeline
- **Case 1**: Reported in <span style="color:blue;">August 2023</span> and confirmed as <span style="color:red;">high severity</span>.  
- **Case 2**: Reported in <span style="color:blue;">August 2023</span> and confirmed as <span style="color:red;">medium severity</span>.  
- **Case 3**: Reported in <span style="color:blue;">February 2024</span> and confirmed as <span style="color:red;">high severity</span>.  

