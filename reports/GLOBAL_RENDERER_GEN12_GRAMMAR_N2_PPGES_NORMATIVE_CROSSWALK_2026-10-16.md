# Gen12 — Grammar v1.3 ⇄ PPGES v1.3.5 ⇄ N2 normative crosswalk

**READ / VERIFY_HASH / REPORT only.** This is an append-only rule-authority crosswalk, not a new method, validation pass, governance transition, policy override, or renderer activation.

- Protected public lock: generation 12 SHA `78909c81f69077666fec07894dd9303e5bc72d5ac6707e4aabc779541cc633b4`.
- Private Library Execution State v2.1 SHA `8bfb41ebe6428eeb6458a4b760ccd87baaef0732555824ca9d1fac91ee3186f3`.
- Authoritative Persian Publication Grammar v1.3 SHA `182589531ab1f2b0302fbc567f93510183af20d4682b99318bf6e4efea364213`.
- PPGES v1.3.5 SHA `8175f477e0d45c25db894fd00fb51cd3bd0ad78ea18b61aaa034a02f725a1371`.
- Full Gen12 OOXML adjudication already merged as PR #31, SHA `7870dd2d8787866d27e407735eaf15ad7459ca581519e10310cc66a1099a87fa`.
- **New exact normative crosswalk**: `/GLOBAL-PUBLICATION/Renderer/Qualification/Gen12-N2-PPGES-Adjudication-2026-10-16/GLOBAL_RENDERER_GEN12_GRAMMAR_N2_PPGES_NORMATIVE_CROSSWALK_2026-10-16.json`, SHA `54e0ef9ad6d915ac73e1ed95faae7bf887f16850735b69fd6f96ca1b9608b83a`. Human-readable .md and .sha256 in the same folder.

| Finding group | Authority-aligned conclusion |
|---|---|
| HEAD-001 (3) | Grammar §3 explicitly requires RTL plus physical Right. Missing effective Right is a genuine structural failure. |
| HEAD-002 (6) | Grammar §3 default permits internally LTR/natural numeric atom **but requires RTL-owned separator**. Frozen N2 pattern differs. Scoped acceptance does not retroactively waive active PPGES for a new output. |
| BODY-001 (5) | Grammar §2 requires Justified for four bodies; §10 requires RTL+Center for the FigureCaption misidentified as normal body. |
| LIST-001 (4) | Grammar §4 requires RTL and physical Right. |
| LIST-002 (12) | Grammar §4 right-hand marker and RTL hanging geometry; frozen N2 left-based lvlJc/indent mismatch is not compliant in an unqualified new assembler. |
| TABLE-001 (1) | Grammar §8.1 requires Center+RTL for header row unless **entire table** is classified fully-English technical. One English header cell in a mixed table does not qualify. |
| ENGSEQ-001 (2 unresolved) | Grammar §7 requires source-level semantic class and evidence for coherent English phrase `CSS level 3`; no blind Persian comma or waiver. |

**Conclusion:** No general PPGES rule weakening is indicated by this evidence. The next *distinct, separately owner-governed* responsibility is defining compliant new semantic roles and OOXML output profiles (explicit Heading/Body/List/Table geometry, caption identity, technical-term classification). Keep N2 13/13 PASS and G.7 52/52 PASS immutable; no edit to N2 or current PPGES, no rerun of failed Gen11 assembler, no DOCX or book BUILD under generation-12 READ_ONLY. Renderer pointer remains `QUALIFICATION_PENDING`.

**Proposed—not selected or authorized—next governance action** `GLOBAL_RENDERER_CANONICAL_PROFILE_CONTRACT_DESIGN_2026_10_16`. Any future mutating work must obtain owner manual GOVERNANCE_UPGRADE to select a distinct exact action, protected gate PASS, and separately authorized EXECUTE if required.
