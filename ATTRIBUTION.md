# Attribution and reference boundary

*English · (Korean version follows in a later release; this file is normative.)*

muster is an unofficial personal project. It is not affiliated with, endorsed by,
or certified by the Korea Internet & Security Agency (KISA) or the Center for
Internet Security (CIS), and it does not replace an official vulnerability
assessment.

## KISA guide

- **Publisher:** Korea Internet & Security Agency (KISA).
- **Document:** 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드, 2026 edition
  (posted 2025-12-24; PDF dated 2025-12-23). The 2021 edition is referenced for
  item-number mapping only.
- **Source:** https://www.kisa.or.kr/2060204 (자료실). The 2021 edition is also
  distributed through the Korean public data portal.
- **Copyright notice as stated on the KISA site:** "Copyright(C) KISA. All rights
  reserved." The public data portal lists the 2021 distribution without a usage
  restriction; because the two statements differ, this repository takes the
  conservative reading.

**What this repository reproduces from the guide:** item codes (U-xx), item names,
categories, importance levels (상/중/하) and page numbers, in `docs/reference/kisa/`
and in the design specification's appendix, as a cross-reference index — the
minimum needed to relate a muster result to an assessment.

**What it does not reproduce:** the guide's inspection text, purpose, threat,
criterion and remediation text, in any file. Control titles, descriptions and
rationale are muster's own wording. The guide itself is linked, not included.

## CIS Benchmarks

CIS publishes non-member Benchmarks under CC BY-NC-SA 4.0, and its Terms of Use
additionally prohibit creating derivative works based directly on a non-member
product and representing a particular level of compliance. Accordingly:

- Controls may reference a CIS recommendation only as benchmark name, benchmark
  version and recommendation number. No recommendation title, text or audit
  procedure is stored; the control schema has no field for them.
- muster judges no CIS compliance and claims no CIS compliance level.

## Checks that are not KISA items

Checks beyond the KISA list (for example mount options, kernel self-protection
sysctls, audit pipeline health) are written from primary sources — kernel
documentation, man pages, distribution documentation — in muster's own wording,
and reproduce no benchmark text.

## Contributions

Contributed controls must follow the same boundary. The pull-request template
asks whether any benchmark or guide text was copied; the answer must be no.
