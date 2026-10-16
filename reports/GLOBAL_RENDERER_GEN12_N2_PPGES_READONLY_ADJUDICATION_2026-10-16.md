# Global Renderer — Gen12 N2 / PPGES read-only adjudication (completed)

**Scope:** READ, VERIFY_HASH, REPORT only. NO BUILD, no new DOCX, no PPGES/Word rerun, no renderer promotion.

Protected lock: generation 12 SHA `78909c81f69077666fec07894dd9303e5bc72d5ac6707e4aabc779541cc633b4`; Library Execution State v2.1 SHA `8bfb41ebe6428eeb6458a4b760ccd87baaef0732555824ca9d1fac91ee3186f3`.

Exact full, append-only Library evidence:
- `/GLOBAL-PUBLICATION/Renderer/Qualification/Gen12-N2-PPGES-Adjudication-2026-10-16/GLOBAL_RENDERER_GEN12_N2_PPGES_RULE_ADJUDICATION_2026-10-16.json`
- JSON SHA-256: `7870dd2d8787866d27e407735eaf15ad7459ca581519e10310cc66a1099a87fa`
- Companion human-readable `GLOBAL_RENDERER_GEN12_N2_PPGES_RULE_ADJUDICATION_2026-10-16.md`, SHA-256 `b86b01e1a8e2f4734a34b3f142f691716e369aee781e39ea082e191170905d9a`.

## Verified by reading frozen N2, failed Gen11 artifact and active PPGES v1.3.5

1. N2 `styles.xml` and `numbering.xml` match failed generated DOCX byte-for-byte. All fourteen N2 exemplar paragraph/table property blocks match their clones, and the fourteen source fragment SHA-256 hashes match.
2. `HEAD-001` (3): effective Right missing in frozen N2 heading profile; structural validator result stands.
3. `HEAD-002` (6): numeric atom RTL and separator natural ownership in original N2 **and** generated headings. This is a current N2/PPGES run-profile conflict, not a newly introduced segment direction. Do not waive PPGES and do not mutate N2.
4. `BODY-001` (5): four non-caption Persian paragraphs lack effective Justify; the fifth is a true FigureCaption source emitted with `NormalWeb` style and centered/RTL properties, hence misclassified as body because durable caption semantic identity was not conveyed.
5. `LIST-001` (4): no effective physical Right.
6. `LIST-002` (12): retained N2 numbering `numId=1,2` uses `lvlJc=left`, left=720 and hanging=360, without positive right/start geometry: a real current rule/profile conflict.
7. `TABLE-001` (1): N2 and generated English-only centered header both lack `w:bidi`; whether English header needs a separate applicability profile is undecided. PPGES remains binding.
8. `ENGSEQ-001` (2 unresolved): `CSS level 3` is one uninterrupted natural English run; semantic technical-literal ownership needs an authoritative profile and was not proven by the failed method.

All 31 precise violation records and two unresolved records with locations/attribution are in the Library JSON. **PPGES gate remains FAIL; Gen11 attempt 01 remains immutable METHOD_FAIL.** No Word Desktop/Mobile or Word-exported PDF tests performed on this new output; N2 13/13 and G7 52/52 scoped PASSES immutable.

**Disposition:** Read-only classification COMPLETE, cross-contract incompatibilities remain BLOCKING. Any future new assembly method or policy resolution needs separate owner-governed authorization. No change to official renderer pointer, which remains `QUALIFICATION_PENDING`.
