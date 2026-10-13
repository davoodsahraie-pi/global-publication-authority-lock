# Global Renderer — Read-Only Additive Gap Map

Date: 2026-10-13  
Mode: READ_ONLY / NO BUILD / NO RENDERER METHOD  
Public lock SHA-256: `9ebf7952318991090fea04801e9636003f6cf15b36db0654c79ddee764740e52`  
Private execution-state SHA-256: `656bac3fc2c9bc370a3667427b338c3ab64b7c83f7f19829f15db442f3f7f656`

## Preserved immutable coverage

The following primitive classes are already locked as scoped PASS and must not be reimplemented or regenerated:

- Heading1
- Heading2
- Heading3
- MixedNumberedHeading
- PersianBullet
- PersianNumbering
- PersianBody
- MixedRTL_LTR
- NumericLTR
- PunctuationBoundary
- TableRTL_LTR
- CodeLTR
- FigureCaption

Additional scoped historical evidence is preserved for Persian suffix handling, diagram glyphs, hyperlink relationships, a real-source pilot, and the dependency capsule. These are not promoted beyond their recorded evidence scope.

## Genuinely pending additive gaps

| Gap | What is missing | Constraint |
| --- | --- | --- |
| Integrated natural-wrap continuity | One project-independent integrated artifact proving long multi-clause LTR islands preserve reading order across natural line wraps inside RTL context | Reuse locked primitives unchanged; integration proof only |
| Composite punctuation ownership | Combined evidence for `= : ; . ( ) — /` around adjacent LTR islands and wrapped mixed paragraphs | Do not reopen the locked PunctuationBoundary primitive |
| Adjacent-LTR island continuity | Evidence that multiple neighboring technical LTR runs remain logically contiguous when Word splits runs for formatting or layout | Integration-only |
| Bold/italic run boundaries | A distinct additive class for emphasis changes inside mixed RTL/LTR sequences, including boundary punctuation | New class only if absent from locked primitives |
| Hyperlink composition | Hyperlink + long LTR phrase + punctuation + surrounding Persian continuity in one project-independent integrated case | Preserve existing hyperlink relationship technique; do not rebuild it |
| Persian suffix composition | Fresh evidence for a Persian suffix adjacent to a technical LTR island in integrated natural-wrap conditions | Evidence gap; no regeneration of the accepted suffix archetype |
| Diagram/caption integration | Diagram technical labels, glyphs, and caption behavior together in an integrated artifact | Preserve locked glyph and FigureCaption primitives |
| Same-artifact cross-device proof | The exact same integrated DOCX SHA must pass Word Desktop and Word Mobile | No per-device regenerated DOCX |
| Word-exported PDF proof | PDF exported by Microsoft Word from that exact DOCX must pass the defined PDF gate | Old N2 reference PDF does not transfer |
| Independent full regression | A deterministic regression over the integrated artifact covering no visible directional controls, logical LTR continuity, punctuation ownership, hyperlinks, tables, lists, code, diagrams, and natural wraps | Must be independent of the renderer method |
| v2 reconstruction PDF evidence | Fresh Word-exported PDF evidence for the existing reconstructed v2 DOCX, if that artifact is used as evidence | Evidence-only; no reserialization |

## Explicitly not gaps

The locked 13 primitive classes are not gaps. Their presence in a future integrated qualification artifact does not authorize reimplementation.

Method C is not a pending gap; it is an immutable METHOD FAIL and may not be patched or resumed.

IMS-REF is not a qualification test bed; it remains frozen and blocked until a project-independent global renderer is fully qualified.

## Future authorization boundary

This report authorizes no build, renderer method, DOCX/PDF generation, fixture creation, pilot, project reopen, or state transition.

A later mutating phase must receive a fresh manual GitHub authorization bound to the exact then-current public lock SHA and private execution-state SHA.

