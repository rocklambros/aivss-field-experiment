AIVSS on three vulnerable labs

I scored 48 findings from damn-vulnerable-ai-agent, agent-sec-lab, and finbot-ctf-demo with the OWASP AIVSS 1.0 calculator (aivss-calc 1.2.0). Three raters each scored every finding. The calculator accepted 143 of 144 payloads.

The short version: AIVSS sits above CVSS-BTE on this set, and the raters do not agree on the band. Reward hacking is the metric that fell apart.

What I ran

Rater A was deepseek/deepseek-v4.1-flash on wafer/us. Rater B was z-ai/glm-5.3 on wafer/us. Rater C was x-ai/grok-4.7 on xai/zdr/us. google/gemini-4-argon had no live US endpoint, so I did not use it. Fallbacks were off, and spend was $5.36.

agent-sec-lab's own pytest suite passed 179 tests with a scripted model and no API key. DVAA's npm test, after npm ci, passed 330 and skipped 39 that need a running fleet. I did not start that fleet. FinBot's stock server binds 0.0.0.0, so I did not use that entry point. I ran the scenarios in finbot_exploits.md on 127.0.0.1:5055 with no model key. FB-01 and FB-04 are E:A. FB-03 is E:P. Scored FB-02 has no payload in that file and stays E:U. The process was killed and the port was closed.

Inflation is real on this set

Of 48 adjudicated findings, 36 are High or Critical under AIVSS (75%). Twenty-two are High or Critical on CVSS-BTE alone (46%). Mean uplift is 1.20 points. agent-sec-lab moves the most (mean uplift 1.63, N=19). DVAA moves less (0.94, N=25). FinBot moves 0.78 (N=4). All four FinBot findings are High or Critical on CVSS-BTE. Three of those scores rose after the localhost run.

AIVSS also throws distinctions away. I counted 16 distinct CVSS-BTE values and 12 distinct AIVSS values. Four path groups share an exploit path. In each of those groups, two of the three raters gave the members the same AIVSS letters. I am not reading those duplicates as extra information loss.

AP is not the switch you might expect

Eleven findings land in Effect Class A2. Zero of them get there only through AP Lateral with LC left at Mediated or None. All 11 also meet the clause for LC Direct or Indirect plus cross-session context. RH Demonstrated does not put any finding into A2. If you came in thinking AP Lateral was the master switch, this corpus does not support that.

Where the raters split

Fleiss kappa on the findings all three could score is 0.64 for LC (N=47), 0.72 for CP (N=38), 0.11 for AP (N=47), and 0.57 for ES (N=47). Effect class is 0.45, the AIVSS band is 0.19, and the CVSS band is 0.08. Intervals are a cluster bootstrap, seed 42, 2000 resamples.

RH has no three-rater kappa. Rater C marked RH unknown on all 48 findings. Rater B marked RH unknown on 8. Rater A marked none unknown. A versus B, on the 39 findings neither marked unknown, agree 59% of the time (kappa 0.28).

The rubric asks for a human-verified episode before you can say Demonstrated, and for a tested isolation before you can say None. These labs do not contain that test. Unknown is a fair reading. Possible is also a fair reading when a tool can hit a success flag. The rubric should say whether a CTF flag counts.

Band fights are mostly mixed. Across 141 pairwise comparisons, 63 pairs disagree on the AIVSS band. One of those is agentic labels only, six are CVSS metrics only, and 56 change both.

You cannot pin the band noise on the agentic metrics alone, because CVSS base metrics are judgment calls too and the raters disagreed there as well.

Exploit maturity moves CVSS more than it moves AIVSS

I re-scored each adjudicated finding under E:X, E:A, E:P, and E:U. The CVSS band changes on 37 of 48 findings. The AIVSS band changes on 17 and stays put on 31. On FB-01, an empty evidence object and an explicit E:U in the vector both come back at CVSS-BTE 7.7. The calculator replaces any E in the vector from the evidence object. Empty evidence becomes E:U. If you type E and pass an empty evidence object, you will not get the E you typed.

Controls

I re-scored with MUI:A, MAT:P, and one step down on MVC and MVI. Where the adjudicated letters allowed it, I also moved ES Wide to None, AP Lateral to Contained, and CP Cross-session to Session. AIVSS moved on 43 of 48 findings. CVSS-BTE moved on 43 of 48. In this pass the two moved together. I did not re-score the labs' own fixed configs line by line (agent-sec-lab's fixes, DVAA's AIM twins). That is still open.

Ordering

A defender's top five changes. By AIVSS: FB-03, FB-04, ASL-S1, ASL-S7, FB-01. By CVSS-BTE: ASL-S7, ASL-S1, FB-01, FB-03, FB-04. By Effect Class then CVSS-BTE: FB-03, FB-04, ASL-S2c, DV-L2-05, ASL-S8b. I counted 238 pairwise inversions between the AIVSS rank and the CVSS-BTE rank (N=48).

What I would not claim

These raters are models. Three families cut single-model bias, and they still share training data and alignment habits. The kappa is a reliability proxy, which the protocol says is not human inter-rater reliability.

The sample is 48 findings. Several kappas are weak because the marginals are lopsided, and RH is the extreme case.

The labs are training targets. agent-sec-lab's E:A rests on a scripted model that obeys injected text by design, so the control fails against a worst case. That run does not tell you how often a production model falls for it.

I wrote the packets. I did not write the FinBot payloads. Those are in finbot_exploits.md. The claim that no artifact was supplied was wrong. Headline maturity follows the localhost run, which used the no-key fallback.

One calculator reject stands: rater B wrote VC:LV on DV-L3-04. I left it rejected.
