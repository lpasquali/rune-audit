---- MODULE AuditChain ----
(*
 * TLA+ specification for the audit evidence chain.
 *
 * SPDX-License-Identifier: Apache-2.0
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS MaxEntries

VARIABLES evidence_log, signed_entries, verified_entries, next_id

vars == <<evidence_log, signed_entries, verified_entries, next_id>>

LogEntries == { evidence_log[i] : i \in 1..Len(evidence_log) }

Init ==
    /\ evidence_log = << >>
    /\ signed_entries = {}
    /\ verified_entries = {}
    /\ next_id = 1

CollectEvidence ==
    /\ next_id <= MaxEntries
    /\ evidence_log' = Append(evidence_log, next_id)
    /\ next_id' = next_id + 1
    /\ UNCHANGED <<signed_entries, verified_entries>>

SignEntry ==
    /\ \E id \in LogEntries :
        /\ id \notin signed_entries
        /\ signed_entries' = signed_entries \union {id}
        /\ UNCHANGED <<evidence_log, verified_entries, next_id>>

VerifyEntry ==
    /\ \E id \in signed_entries :
        /\ id \notin verified_entries
        /\ \A smaller \in signed_entries :
            (smaller < id) => (smaller \in verified_entries)
        /\ verified_entries' = verified_entries \union {id}
        /\ UNCHANGED <<evidence_log, signed_entries, next_id>>

GenerateReport ==
    /\ Len(evidence_log) > 0
    /\ UNCHANGED vars

Next == \/ CollectEvidence \/ SignEntry \/ VerifyEntry \/ GenerateReport

Spec == Init /\ [][Next]_vars /\ WF_vars(SignEntry) /\ WF_vars(VerifyEntry)

SignedInLog == signed_entries \subseteq LogEntries
VerifiedAreSigned == verified_entries \subseteq signed_entries
VerifiedStable == verified_entries \subseteq LogEntries

NoGapsInVerified ==
    \A id \in verified_entries :
        \A smaller \in LogEntries :
            (smaller < id /\ smaller \in signed_entries) => smaller \in verified_entries

SafetyInvariant == SignedInLog /\ VerifiedAreSigned /\ NoGapsInVerified /\ VerifiedStable

====
