---- MODULE ComplianceMatrix ----
(*
 * TLA+ specification for IEC 62443 compliance tracking.
 *
 * SPDX-License-Identifier: Apache-2.0
 *)

EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Requirements, EvidenceItems, MaxMappings

VARIABLES evidence_map, compliance_status, reset_log

vars == <<evidence_map, compliance_status, reset_log>>

NOT_MET == 0
PARTIALLY_MET == 1
MET == 2
StatusValues == {0, 1, 2}

Init ==
    /\ evidence_map = [r \in Requirements |-> {}]
    /\ compliance_status = [r \in Requirements |-> NOT_MET]
    /\ reset_log = << >>

MapEvidence ==
    /\ \E r \in Requirements : \E e \in EvidenceItems :
        /\ e \notin evidence_map[r]
        /\ evidence_map' = [evidence_map EXCEPT ![r] = @ \union {e}]
        /\ UNCHANGED <<compliance_status, reset_log>>

UpdateStatus ==
    /\ \E r \in Requirements : \E new_status \in StatusValues :
        /\ new_status > compliance_status[r]
        /\ (new_status >= PARTIALLY_MET) => (evidence_map[r] /= {})
        /\ (new_status = MET) => (compliance_status[r] = PARTIALLY_MET)
        /\ compliance_status' = [compliance_status EXCEPT ![r] = new_status]
        /\ UNCHANGED <<evidence_map, reset_log>>

ResetStatus ==
    /\ \E r \in Requirements :
        /\ compliance_status[r] > NOT_MET
        /\ compliance_status' = [compliance_status EXCEPT ![r] = NOT_MET]
        /\ evidence_map' = [evidence_map EXCEPT ![r] = {}]
        /\ reset_log' = Append(reset_log, r)

GenerateGaps ==
    /\ \E r \in Requirements : evidence_map[r] = {}
    /\ UNCHANGED vars

Next == \/ MapEvidence \/ UpdateStatus \/ ResetStatus \/ GenerateGaps

Spec == Init /\ [][Next]_vars

MetRequiresEvidence ==
    \A r \in Requirements :
        (compliance_status[r] >= PARTIALLY_MET) => (evidence_map[r] /= {})

ValidEvidence ==
    \A r \in Requirements : evidence_map[r] \subseteq EvidenceItems

SafetyInvariant == MetRequiresEvidence /\ ValidEvidence

====
