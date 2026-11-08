# Round 1 Red Teamer, raw (condensed)
1. No source text reached raters: packets hold citations only (build_packets.py:50-51), 0 packets with code text. Lead prose encodes answers (e.g. FinBot tool_binding "Five fixed tools ... No dynamic tools" = ES:N). Critical, Very likely. Fix: embed bounded verbatim cited excerpts in delimited untrusted block; rerun.
2. Lead applicability leaked via nested agents[].applicability in ASL and FinBot profiles; filter only top-level (execute_raters_secure.py:239-245). Rater A rationale 0.60-0.85 similar to lead. H8 23/25 split = lab boundary. High, Very likely. Fix: recursive strip + assertion; rerun.
3. Lab-wide memory profile spills into per-path CP: ASL-S2b, S5a (majority C), S2c, S5c (tie->A) all A2 via CP:C. 4 of 11 A2 rest on spillover. High, Likely. Fix: path-scoped instruction; rerun.
4. AIVSS scoring target undefined (only cvss says "default configuration"); DVAA steps carry both readings; 9 of 10 DVAA LC splits from scripted default. Mixed-config vectors (DV-L3-03 CVSS 2.0 + A2). High, Very likely. Fix: explicit target for all metrics; DVAA as implemented vs as modeled.
5. Approved scope ~58 (R7) not executed; 48 delivered, reconstructed DVAA classes not scored; no ruling. All DVAA poc true. High, Likely. Fix: score them or log deviation.
6. Rubric sent lacks effect_class ladder, classify_rh, FIRST CVSS text; includes lookup table 9.7/10.0 (outcome visibility). Medium, Likely. Fix: supply rules, remove lookup tables.
7. lab_label/impact/title carry ASI/LLM IDs and verdict titles. Medium, Plausible. Fix: neutralize.
8. Verbatim payloads reach raters unevenly by lab; only one-sentence guard; no canary. Low, Unlikely steered. Fix: drop injection_text_observed, untrusted delimiters, canary.
9. Decision framing precedes data; lead framed inputs and recommendation (REPORT.md:7-9). Medium, Plausible. Fix: separate decision memo; disclose.
