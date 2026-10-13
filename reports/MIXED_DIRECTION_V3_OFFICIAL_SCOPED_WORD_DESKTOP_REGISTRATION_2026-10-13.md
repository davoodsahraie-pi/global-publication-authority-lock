# Official scoped registration — Mixed Direction Delta Fixture v3

Date: 2026-10-13
Status: **APPROVED SCOPED WORD DESKTOP FIXTURE — only after protected main merge and `publication-authority` PASS**.

## Authorized scope and hashes

- Action ID: `REGISTER_MIXED_DIRECTION_V3_ADDITIVE_FIXTURE`.
- Manual EXECUTE authorization: [GitHub workflow 38375365548](https://github.com/davoodsahraie-pi/global-publication-authority-lock/actions/runs/38375365548), outcome success.
- Exactly authorized operations: `UPLOAD_OFFICIAL`, `PROMOTE`; `target_scope_ids: []`.
- Protected public lock SHA-256: `338cdcb09c91df098d1508670642330cbd108612c63d3141c452a4d13bca16bf`.
- Private Library Execution State SHA-256: `ea2ea80acb8c54c40e1398ff49cea067297fb3ebd9343f5997ce09edd4f3c6db`.
- Approved immutable DOCX SHA-256: `e0b0069933994cc82fbc50d8a3c1254e48d142ad01069757f45771047e586954`.
- Exact DOCX size: 33130 bytes.

## Verified Library artifacts (exact filenames)

- `/GLOBAL-PUBLICATION/Renderer/Qualification/Mixed-Direction-v3-2026-10-13/MIXED_DIRECTION_DELTA_REVIEW_CANDIDATE_v3_HEADING4_RIGHT.docx`
- `/GLOBAL-PUBLICATION/Renderer/Qualification/Mixed-Direction-v3-2026-10-13/MIXED_DIRECTION_V3_SCOPED_REGISTRATION_MANIFEST_2026-10-13.json` — SHA-256 `4eaf7b5f0854d38c1aae4c60f2409ba4f516bc6652cf18b2d9296b9a27a4ce10`.
- `/GLOBAL-PUBLICATION/Renderer/Qualification/Mixed-Direction-v3-2026-10-13/MIXED_DIRECTION_V3_SCOPED_WORD_DESKTOP_REGISTRATION_2026-10-13.md` — SHA-256 `300a2949d5f30f35e99b271cb658be375e34fe86bb6a93d8cbbdb1959b7cffec`.

The three Library files were re-materialized after uploading, and their SHA-256 values matched the uploaded originals. The DOCX is an intact OOXML package with the expected labels and no prohibited directional controls in visible text.

## Four independent test cases

1. Regular Persian RTL body with separate English LTR runs; **no** blanket technical-Left exception.
2. `Destination A:`: purely English label LTR + physical Left; Persian/mixed payload RTL + physical Left.
3. `Destination B:`: same role-specific left block with natural long-line wrapping.
4. Punctuation and `Decision A:` block: special English label LTR + Left, Persian/mixed payload RTL + Left; the ordinary title `آزمون ۴ — مالکیت علامت‌ها در مرز جهت` remains RTL + physical Right.

The **three** technical-block Left exceptions do not apply to ordinary Persian body, mixed sentences, or headings. The user explicitly approved the exact v3 Word Desktop rendering and limited the approval to these scoped cases.

## Gate status and non-promotion

- Structural / OOXML: **PASS**.
- Word Desktop (user attestation on exact v3): **PASS — scoped**.
- Word Mobile for this exact v3 DOCX: **NOT ATTESTED**.
- Word-exported PDF for this exact v3 DOCX: **NOT ATTESTED**.
- Global renderer status: **QUALIFICATION_PENDING**, not QUALIFIED.

## Immutable and governance boundaries

- N2 and all thirteen independently verified Method K Word-native primitive scopes remain immutable and unchanged.
- Existing immutable PASS hashes, METHOD FAIL hashes (including Method C), frozen project and blocked project scopes remain unchanged.
- No IMS work, project build, DOCX rebuild, renderer reimplementation, or general policy rewrite.
- No Execution State Current, public lock, or Renderer Current pointer mutation is included in this EXECUTE registration.
- **Append-only ledger caveat:** the registration is a protected-main scoped evidence record, not an additional entry in the machine `ledger_hashes.immutable_pass` array. Such a state/ledger mutation requires a separately authorized governance transition; do not assert it occurred here.

Officiality is conferred only by successful `publication-authority` check followed by a merge to protected `main`; an open PR alone is not official.
