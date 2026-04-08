---- MODULE GateAggregation ----
(*
 * TLA+ specification for cross-repo gate aggregation.
 *
 * SPDX-License-Identifier: Apache-2.0
 *)

EXTENDS Integers, FiniteSets

CONSTANTS Repos, Gates

VARIABLES repo_gates, aggregate_status, reported

vars == <<repo_gates, aggregate_status, reported>>

PASS == "pass"
FAIL == "fail"
PENDING == "pending"
StatusSet == {PASS, FAIL, PENDING}

ComputeAggregate ==
    IF \E r \in Repos : \E g \in Gates : repo_gates[r][g] = FAIL
    THEN FAIL
    ELSE IF \A r \in Repos : \A g \in Gates : repo_gates[r][g] = PASS
    THEN PASS
    ELSE PENDING

Init ==
    /\ repo_gates = [r \in Repos |-> [g \in Gates |-> PENDING]]
    /\ aggregate_status = PENDING
    /\ reported = {}

GatePass ==
    /\ \E r \in Repos : \E g \in Gates :
        /\ repo_gates[r][g] = PENDING
        /\ repo_gates' = [repo_gates EXCEPT ![r][g] = PASS]
        /\ aggregate_status' = ComputeAggregate'
        /\ reported' = IF \A gate \in Gates : repo_gates'[r][gate] /= PENDING
                       THEN reported \union {r} ELSE reported

GateFail ==
    /\ \E r \in Repos : \E g \in Gates :
        /\ repo_gates[r][g] = PENDING
        /\ repo_gates' = [repo_gates EXCEPT ![r][g] = FAIL]
        /\ aggregate_status' = FAIL
        /\ reported' = IF \A gate \in Gates : repo_gates'[r][gate] /= PENDING
                       THEN reported \union {r} ELSE reported

RecalculateAggregate ==
    /\ aggregate_status' = ComputeAggregate
    /\ UNCHANGED <<repo_gates, reported>>

Next == \/ GatePass \/ GateFail \/ RecalculateAggregate

Spec == Init /\ [][Next]_vars

FailPropagation ==
    (\E r \in Repos : \E g \in Gates : repo_gates[r][g] = FAIL)
        => (aggregate_status /= PASS)

PassRequiresAll ==
    (aggregate_status = PASS)
        => (\A r \in Repos : \A g \in Gates : repo_gates[r][g] = PASS)

SafetyInvariant == FailPropagation /\ PassRequiresAll

====
