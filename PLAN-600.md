# ScamShield MY — False-Positive-Free Risk Planning (600-item checklist)

## Goal
Phone number risk scoring that avoids flagging legit Malaysians as scammers while catching actual scam activity.

## Core Principle: Risk != Number Range
A 013 number isn't automatically a scam. Scammers use 012, 016, 019 too. Flag based on BEHAVIOR + CONTEXT, not just prefixes.

---

## Phase 1: Data Sources (1-50)

### 1-10: Official Trusted Databases
1. Register with MCMC SMA (Malaysian Communications and Multimedia Commission – Spam Message Analyst)
2. Subscribe to MCMC blacklist feed (scam numbers reported to Suruhanjaya)
3. Integrate with Bank Simpan Prihatin scam alert API (if available)
4. Cross-check with Bank Negara’s approved financial scam list
5. Add PDRM CyberSecurity scam hotline number list
6. Add JPN (Jabatan Pendaiban Negara) impersonation scam list
7. Add Kementerian Kesihatan scam numbers (fake medicine)
8. Add Polis Diraja scam list (fake police)
9. Add customs / KLIA / airport scam list
10. Add Education Ministry / UPU scam list

### 11-20: User-Community Reporting
11. Create in-repo /report endpoint for community submissions
12. Accept screenshot uploads of WhatsApp scam messages
13. Parse sender name from report (e.g., “Pos Laju”, “DHL”, “Bank Simpan”)
14. Parse message text (regex for OTP phishing, “click link”, “account locked”)
15. Deduplicate identical reports (>1 report per number = escalate)
16. Weight reports from verified users higher
17. Age-weighted trust decay (reports >6 months old decay)
18. Tag reports by scam TYPE (not just number): OTP-phish, fake-official, love-scam, investment-fraud
19. Store reports with timestamp + reporter IP (for abuse prevention)
20. Expose aggregate report count as /api/<number>/reports

### 21-30: Cross-Platform Intelligence
21. Import WhoisXML / Numverify data for prefix ownership
22. Map number → carrier (Maxis, DiGi, U Mobile, Celcom, Unifi)
23. Flag recycled prepaid SIM cards (recycled numbers reused by scammers)
24. Compare against Twilio Lookup (if API key added)
25. Check against Nexmo Number Insight (if available)
26. Cross-check with Facebook/Meta Business verified business directory
27. Cross-check Instagram verified business directory
28. Check Malaysia Companies Commission (SSM) business registry
29. Check against Google Verified SMS sender list
30. Check against WhatsApp Business verified directory

### 31-40: Real-Time Signal
31. Google Safe Browsing API check on domains in message
32. Check URL shorteners (bit.ly, tinyurl) expansion
33. DNSBL spamhaus check on domains/IPs
34. TLS certificate validity check on claimed domains
35. WHOIS creation date check (new domains = higher risk)
36. Reverse IP lookup (shared hosting = suspicious for banks)
37. Check URL redirection chains
38. Check for typosquatted domains (e.g., “maybaank” vs “maybank”)
39. Check against known scam landing pages
40. Check message for urgency/emoji overload (psychological manipulation markers)

### 41-50: Contextual Scoring
41. Cross-check sender ID against registered business name (SSM)
42. Cross-check claim (e.g., “Bank Simpan” message from 013 number)
43. Check if number has been ported recently (port-out scams)
44. Check if number is VoIP / non-geographic (higher risk)
45. Check if number is premium rate (e.g., 19xx)
46. Look up number in commercial databases (if key available)
47. Check if number appears on known scam forums/Discord
48. Historical traffic patterns (spammy = many short calls)
49. Cross-check with MyNumber (Malaysia mobile prefix allocation)
50. Validate prefix is actually assigned to a Malaysian carrier

---

## Phase 2: Scoring Logic (51-200)

### 51-60: Base Score Model
51. Start base score at 0
52. Each confirmed scam report: +20 points
53. Each community (non-scam) report: -5 points
54. Number in official government blacklist: +50
55. Number in Bank Negara scam list: +60
56. Number is premium rate (19xx): +40
57. Number is VoIP/prepaid: +15
58. Number is ported within last 30 days: +10
59. Number belongs to a legitimate business (SSM verified): -30
60. Number is verified on WhatsApp Business API: -40

### 61-80: Message-Based Scoring (if message provided)
61. Contains urgent language (“immediate action”, “urgent”, “within 24h”): +10
62. Contains OTP request or OTP mention: +15
63. Contains URL: +5
64. URL points to shortened link: +5
65. URL points to .tk/.ml domain: +20
66. URL contains typosquatted brand name: +20
67. Message contains attachment: +15
68. Message contains invoice/quote scam language: +10
69. Fake courier (Pos Laju / DHL) + link: +25
70. Fake bank alert + link: +30
71. Fake government agency + link: +40
72. Fake police/immigration threat: +35
73. Investment/fake gold scheme language: +15
74. Love scam/emotional manipulation keywords: +10
75. Job offer / work-from-home keyword: +10
76. Gambling promotion (slots, blackjack): +10
77. Lottery / prize / inheritance claim: +20
78. Debt collector impersonation: +25
79. Utility bill impersonation (Tenaga, Syabas): +15
80. EPF/Social Security impersonation: +15

### 81-120: Carrier / Infrastructure Scoring
81. Carrier is unregistered/virtual (e.g., Tronboard, Digi): +5
82. Carrier is foreign (Singapore, Indonesia number claiming to be MY): +30
83. Carrier is toll-free (1800, 1700): +5 (scammers use these)
84. Number is on Do_not_call registry: neutral (no score change)
85. Number has been recycled (prepaid churn): +10
86. Number has high call volume spikes: +10
87. Number uses CLI spoofing detected: +25
88. Number flagged by telco spam detection (Celcom/Xpax spam block): +20
89. Number is on Maxis SPAM blocklist: +20
90. Number is on DiGi SPAM filter: +20
91. Number is on U Mobile spam list: +20
92. Number is flagged by Google Call Screen: +25
93. Number has international format but claims local use: +10
94. Number prefix not in official MCMC allocation: +15
95. Number is a new registration (<30 days old): +10
96. Number is a virtual phone number provider: +15
97. Number is on Twilio/Plivo (bulk SMS): +20
98. Number is on Nexmo/Vonage: +20
99. Number uses non-standard format: +5
100. Number has no valid checksum (Luhn-style validation on mobile numbers): +5

### 101-150: Trust / Mitigation Factors
101. Number registered to verified business name (SSM check): -30
102. Number has official shortcode (1300, 1800): -5 (still scam possible)
103. Number is on official government contact list: -40
104. Number is on official bank support hotline list: -40
105. Number is on official hospital/police emergency: -50
106. Number has been in use >2 years (long-standing): -10
107. Number belongs to verified WhatsApp Business: -20
108. Number has no spam reports (clean): -5 per month clean (min -20)
109. Number has community “legit” tags (food delivery, sales): -10
110. Number is on white-hat registry (legit marketers): -15
111. Number is a registered telco (not resold): -5
112. Number is a fixed-line (less common for scams): -5
113. Number is from known legit business group (e.g., chain restaurant HQ): -20
114. Number has verified social media business profile: -15
115. Number is on official e-commerce platform seller verified: -10
116. Number has reverse lookup showing real person name: -5
117. Number is flagged by users as “not a scam” (counter-report): -10 each
118. Number has been appealed/reviewed by moderator: -10 if cleared
119. Number is on holiday/blackout scam watchlist but not currently active: 0
120. Number has recent scam activity but was registered 2+ years ago: neutral

### 121-150: Behavioral Patterns
121. Multiple numbers from same IMEI reported: +15
122. Multiple numbers from same IP reported: +10
123. Report cluster detected (same sender, different numbers): +20
124. Report spike in last 24h: +15
125. Report spike in last 7 days: +10
126. Weekend surge pattern (common for scams): +5
127. Number appears in bulk SMS dump: +15
128. Number part of known scraper botnet: +30
129. Number uses sequential dialing (01X-0000001, 01X-0000002): +10
130. Number has very short call duration (<5s): +5
131. Number blocks after first ring: +5
132. Number auto-rejects unknown callers: +5
133. Number forwards to premium service: +20
134. Number is an AVD (answering service) used by scammers: +10
135. Number registered with fake name: +15
136. Number uses proxy registration: +10
137. Number appears in leaked data dumps: +20
138. Number appears on dark web marketplace: +40
139. Number linked to cryptocurrency exchange registration: neutral
140. Number linked to payment wallet (GrabPay, ShopeePay): neutral

### 141-200: Threshold Adjustments
141. Default risk threshold: LOW (0-20), MEDIUM (21-50), HIGH (51-75), CRITICAL (76+)
142. Auto-flag as DANGER at score >= 75
143. Auto-clear (SAFE) at score <= -20
144. Auto-reset score decay: -5 per week with no new reports
145. Score floor: -50 (never below)
146. Score ceiling: 200 (always DANGER)
147. New unknown number with no data: SUSPICIOUS (score 15)
148. Number reported by verified source (PDRM, MCMC): minimum 50
149. Number reported only once by anonymous user: +10
150. Number reported by 3+ independent users: minimum 30
151. Number with conflicting reports (some say scam, some say legit): SUSPICIOUS
152. Number has report ratio >70% scam: scale to DANGER
153. Number has report ratio >50% scam: scale to HIGH
154. Number with majority legit reports: scale down to SAFE
155. Time-based decay applied every 24h
156. Re-check blacklisted numbers every 6h
157. Re-score on each new report (incremental)
158. Auto-suspend scoring for numbers in active investigation
159. Manual review queue threshold: score 40-59
160. Auto-publish DANGER list to public API
161. Auto-publish SAFE/CLEAN list to public API (for verification)
162. Allow user to flag false-positive
163. Allow user to flag missed scam
164. Moderator review of flagged numbers
165. Moderator override (lock score)
166. Audit log of all scoring changes
167. Export reports for law enforcement
168. GDPR/MCMC compliance (no personal data logging)
169. No permanent IP storage (hashing after 24h)
170. Report-only mode (no auto-flag yet)

---

## Phase 3: API Endpoints (201-400)

### 201-250: Read Endpoints
201. GET /api/check?q=013... → returns score + status + last_seen
202. GET /api/<number>/reports → list community reports
203. GET /api/<number>/score/history → scoring timeline
204. GET /api/trends → trending scam types today
205. GET /api/trends/week → weekly trending
206. GET /api/blacklist → full blacklist export
207. GET /api/whitelist → trusted numbers
208. GET /api/stats → daily stats summary
209. GET /api/stats/week → weekly stats
210. GET /api/stats/region → scam by Malaysian state
211. GET /api/scams/types → enum list
212. GET /api/reporters → list contributor handles (not PII)
213. GET /api/<number>/carrier → carrier lookup
214. GET /api/<number>/whois → ownership data
215. GET /api/domains → trending scam domains
216. GET /api/urls → trending scam URLs
217. GET /api/patterns → common scam message templates
218. GET /api/senders → common sender names (e.g., "SPM", "HR1", "PosLaju")
219. GET /api/numbers/format → number normalization helper
220. GET /api/healthz → health check
221. GET /api/version → API version + uptime
222. GET /api/docs → OpenAPI spec
223. GET /api/metrics → Prometheus metrics
224. GET /api/config → public scoring config (thresholds only)
225. GET /api/languages → supported languages (en, ms, zh, ta)
226. GET /api/regions → Malaysia states list
227. GET /api/carriers → Malaysian carrier list
228. GET /api/prefixes → prefix allocation table
229. GET /api/prefixes/danger → danger prefix ranges
230. GET /api/prefixes/safe → safe prefix ranges

### 231-300: Write Endpoints
231. POST /api/report → submit community report (with captcha/email token)
232. POST /api/report/bulk → bulk upload (moderator only)
233. POST /api/flag/false-positive → flag false positive
234. POST /api/flag/missed-scam → flag missed scam
235. POST /api/verify → verify a number is legit (trusted partners)
236. POST /api/blacklist/add → moderator add to blacklist
237. POST /api/blacklist/remove → moderator remove from blacklist
238. POST /api/whitelist/add → add to whitelist
239. POST /api/whitelist/remove → remove from whitelist
240. POST /api/score/override → moderator score override
241. POST /api/bulk/check → check 100 numbers at once (rate-limited)
242. POST /api/scan/message → scan full SMS message for scam patterns
243. POST /api/scan/url → scan a URL for scam/phishing
244. POST /api/scan/attachment → scan image attachment OCR text for scam
245. POST /api/comment → add comment to a report
246. POST /api/vote → upvote/downvote a report
247. POST /api/verify/email → verify reporter email
248. POST /api/verify/business → verify business identity
249. POST /api/admin/import → import third-party blacklist (admin only)
250. POST /api/admin/export → export full dataset (admin only)

### 251-400: Admin / Moderator Endpoints
251. GET /api/admin/reports/pending → pending moderation queue
252. PATCH /api/admin/report/<id>/approve → approve report
253. PATCH /api/admin/report/<id>/reject → reject report
254. PATCH /api/admin/report/<id>/dismiss → dismiss as false positive
255. GET /api/admin/dashboard → moderation dashboard
256. GET /api/admin/dashboard/today → today’s stats
257. GET /api/admin/dashboard/week → weekly stats
258. GET /api/admin/users → list moderators/admins
259. POST /api/admin/users → create moderator
260. DELETE /api/admin/users/<id> → delete moderator
261. PATCH /api/admin/users/<id> → update moderator
262. GET /api/admin/settings → view settings
263. PATCH /api/admin/settings → update settings
264. POST /api/admin/train → retrain ML model
265. GET /api/admin/train/status → training job status
266. POST /api/admin/cache/clear → clear caches
267. POST /api/admin/db/backup → backup database
268. POST /api/admin/db/restore → restore from backup
269. GET /api/admin/logs → recent logs
270. GET /api/admin/logs/errors → error logs
271. DELETE /api/admin/report/<id> → hard delete report
272. POST /api/admin/report/<id>/escalate → escalate to law enforcement
273. GET /api/admin/report/<id>/evidence → collect all evidence
274. POST /api/admin/ban/user → ban reporter
275. POST /api/admin/unban/user → unban reporter
276. GET /api/admin/audit → audit log
277. GET /api/admin/stats/reports → report volume stats
278. GET /api/admin/stats/users → user activity stats
279. GET /api/admin/stats/blocked_ips → blocked IPs
280. POST /api/admin/ip/block → block IP
281. DELETE /api/admin/ip/<ip>/unblock → unblock IP
282. GET /api/admin/feeds → list external feeds
283. POST /api/admin/feeds/refresh → refresh all feeds
284. PATCH /api/admin/feeds/<id> → update feed config
285. DELETE /api/admin/feeds/<id> → remove feed
286. POST /api/admin/feeds → add new feed
287. GET /api/admin/domains/blacklist → blocked domains
288. POST /api/admin/domains/blacklist → block a domain
289. DELETE /api/admin/domains/blacklist/<domain> → unblock
290. GET /api/admin/urls/blacklist → blocked URLs
291. POST /api/admin/urls/blacklist → block a URL
292. DELETE /api/admin/urls/blacklist/<url> → unblock
293. GET /api/admin/senders/blocklist → blocked sender IDs
294. POST /api/admin/senders/blocklist → add sender block
295. DELETE /api/admin/senders/blocklist/<sender> → remove
296. GET /api/admin/scoring/rules → view scoring rules
297. PATCH /api/admin/scoring/rules → update scoring weights
298. POST /api/admin/scoring/recompute → force recompute all scores
299. GET /api/admin/scoring/stats → scoring distribution
300. POST /api/admin/scoring/reset → reset all scores (nuclear option)

### 301-400: Background Job Endpoints
301. Trigger daily feed refresh
302. Trigger weekly report digest
303. Trigger monthly stats export
304. Trigger annual audit
305. Trigger real-time spam detection job
306. Trigger URL scan queue
307. Trigger domain reputation refresh
308. Trigger carrier database update
309. Trigger SSM business registry sync
310. Trigger MCMC blacklist sync
311. Trigger PDRM scam list sync
312. Trigger Bank Negara scam list sync
313. Trigger Google Safe Browsing refresh
314. Trigger DNSBL check refresh
315. Trigger WHOIS data refresh
316. Trigger number portability check
317. Trigger recycled number detection
318. Trigger VoIP/Virtual number detection
319. Trigger premium rate number check
320. Trigger international spoofing detection
321. Trigger SMS spam pattern learning
322. Trigger ML model inference batch
323. Trigger ML model retraining batch
324. Trigger image OCR batch (screenshot texts)
325. Trigger URL expansion batch
326. Trigger domain age check batch
327. Trigger typosquat detection batch
328. Trigger sender ID verification batch
329. Trigger number reputation graph update
330. Trigger cross-platform correlation (FB, IG, Google)

---

## Phase 4: Moderation / Review System (401-550)

### 401-450: Report Submission
401. User submits report with number + message + screenshot
402. System auto-normalizes number (strip 0/+60)
403. System auto-detects message language (MS/EN/CN/IN)
404. System auto-tags scam type (regex + ML)
405. System auto-extract domains/URLs from message
406. System auto-extract sender ID/name
407. System auto-scales risk score from content
408. System checks if number is already reported
409. System checks for duplicates (fuzzy match)
410. System flags potential abuse (same IP/user, multiple reports)
411. System applies rate limit (5 reports/hour per IP)
412. System applies CAPTCHA for anonymous reporters
413. System offers email verification for trusted reporters
414. System offers SMS verification for Malaysian users
415. System logs submission with timestamp + IP hash
416. Report enters pending queue (score updated after review)
417. System sends confirmation email/SMS to reporter (optional)
418. System notifies reporter when report is reviewed
419. System notifies reporter if report changes outcome (false positive)
420. System archives old reports (>1 year)
421. Reports auto-expire after 730 days (2 years)
422. System allows reporter to edit own report within 24h
423. System allows reporter to delete own report
424. System allows reporter to add evidence (additional screenshot)
425. System auto-redacts personal info from message text
426. System hashes reporter IP after 24h (GDPR)
427. System logs moderator actions (audit trail)
428. System blocks known-abuser IPs
429. System supports anonymous reports (no IP tied to name)
430. System supports verified reports (higher trust weight)

### 431-500: Review Workflow
431. New reports appear in pending queue
432. Moderator reviews report priority (high-score first)
433. Moderator views message + extracted URLs
434. Moderator views screenshot (OCR text available)
435. Moderator checks sender ID legitimacy
436. Moderator cross-checks domains in SafeBrowsing
437. Moderator checks domain WHOIS
438. Moderator checks if domain is live/phishing
439. Moderator checks for typosquatting
440. Moderator checks if number belongs to legit business
441. Moderator checks SSM registry for business name
442. Moderator checks WhatsApp Business verified status
443. Moderator can approve report (add to blacklist)
444. Moderator can reject report (insufficient evidence)
445. Moderator can mark as FALSE POSITIVE (remove if previously blacklisted)
446. Moderator can mark as LOW RISK (score 10-20)
447. Moderator can mark as HIGH RISK (score 50-80)
448. Moderator can mark as CRITICAL (score 80+)
449. Moderator can assign a scammer group label (e.g., “Job scam”, “Love scam”)
450. Moderator can assign a region tag (e.g., “Klang”, “Penang”)
451. Moderator can link reports to a campaign (group)
452. Moderator can upload evidence files (PDF, JPG)
453. Moderator can add private notes (not visible to reporters)
454. Moderator can add public notes (visible to reporters)
455. Moderator can flag for law enforcement handoff
456. Moderator can request additional info from reporter
457. Moderator can merge duplicate reports
458. Moderator can split reports that cover multiple numbers
459. Moderator can escalate to senior moderator (score >= 80)
460. Moderator can assign trusted reporter badge
461. Moderator can revoke trusted reporter badge
462. Moderator can ban reporter (spam/abuse)
463. Moderator can unban reporter
464. Moderator can view reporter history (all past reports)
465. Moderator can view reporter trust score
466. Moderator can view number submission history
467. Moderator can view number scoring timeline
468. Moderator can manually adjust number score
469. Moderator can pin important reports
470. Moderator can unpin reports
471. Moderator can export single report as PDF
472. Moderator can export report evidence package
473. Moderator can add report to public gallery (anonymized)
474. Moderator can suppress report visibility (active investigation)
475. Moderator can schedule report review reminder
476. Moderator can bulk-action (approve 50 at once)
477. Moderator can bulk-action (reject 50 at once)
478. Moderator can bulk-action (recompute scores)
479. Moderator can view moderation activity log
480. Moderator can view moderation performance metrics

### 481-550: Moderation Quality Control
481. Track moderator agreement rate (cross-check)
482. Track moderator speed (avg time to review)
483. Track moderator false-positive rate
484. Track moderator false-negative rate
485. Auto-assign review conflict to senior mod
486. Require 2 moderators for score >= 90
487. Require 2 moderators for blacklist add
488. Log all moderator edits to score
489. Notify senior mod if junior mod disagrees with senior
490. Allow appeal to senior mod
491. Allow appeal to admin
492. Track reporter appeal success rate
493. Auto-flag moderators with high false-positive rates
494. Auto-flag moderators with low activity
495. Moderator peer review (random 5% sample)
496. Moderator calibration test (monthly quiz)
497. Moderator certification (initial + annual)
498. Moderator NDA requirement for sensitive cases
499. Moderator access log (who viewed what)
500. Moderator impersonation detection (shared accounts)
501. Moderator timeout if inactive >90 days
502. Moderator role hierarchy (viewer → reviewer → senior → admin)
503. Moderator permissions matrix
504. Moderator two-factor auth requirement
505. Moderator session timeout (30 min idle)
506. Moderator IP allowlist
507. Moderator activity heatmap
508. Moderator leaderboard (reports reviewed per day)
509. Moderator badges/achievements
510. Moderator retirement process
511. Moderator code of conduct
512. Moderator incident response procedure
513. Moderator handover protocol
514. Moderator backup procedure
515. Moderator training material repository
516. Moderator shadowing program (new mods watch seniors)
517. Moderator exit procedure
518. Moderator access revocation
519. Moderator non-disclosure agreement
520. Moderator data handling guidelines
521. Moderator bias awareness training
522. Moderator conflict of interest policy
523. Moderator public transparency report
524. Moderator quarterly review
525. Moderator feedback system (from reporters)
526. Moderator escalation path
527. Moderator emergency contact
528. Moderator backup contact
529. Moderator vacation mode
530. Moderator shift scheduler

### 531-600: ML & Automation
531. Train message classifier on reported SMS texts
532. Train image classifier on scam screenshot OCR text
533. Train URL reputation model
534. Train domain age/reputation model
535. Train sender ID legitimacy classifier
536. Train number behavior anomaly detector
537. Cross-reference with WhatsApp spam database
538. Cross-reference with Telegram spam database
539. Cross-reference with Facebook scam page registry
540. Cross-reference with Google Safe Browsing
541. Auto-update ML model weekly
542. A/B test ML vs human moderation
543. ML confidence threshold settings
544. ML feedback loop (moderator corrections retrain)
545. ML false-positive alert to moderators
546. ML false-negative alert to moderators
547. ML model explainability (why flagged)
548. ML shadow mode (parallel run with human)
549. ML human-in-the-loop override
550. ML model drift detection
551. ML model version tracking
552. ML model rollback capability
553. ML model canary deployment
554. ML model feature importance audit
555. ML model bias audit by demographic
556. ML model audit by number prefix
557. ML model audit by carrier
558. ML model audit by region
559. ML model audit by language
560. ML model audit by time of day
561. ML model audit by reporting channel
562. ML model audit by reporter type
563. ML model audit by scam type
564. ML model audit by evidence quality
565. ML model audit by number history
566. ML model audit by community trust
567. ML model audit by message length
568. ML model audit by URL count
569. ML model audit by attachment presence
570. ML model audit by sender reputation
571. ML model audit by domain reputation
572. ML model audit by carrier risk
573. ML model audit by geographic risk
574. ML model audit by temporal patterns
575. ML model audit by network topology
576. ML model audit by behavioral clusters
577. ML model audit by social graph
578. ML model audit by financial signals
579. ML model audit by technical indicators
580. ML model audit by linguistic features
581. ML model audit by psycholinguistic markers
582. ML model audit by metadata features
583. ML model audit by provenance signals
584. ML model audit by trust signals
585. ML model audit by reputation aggregates
586. ML model audit by consensus signals
587. ML model audit by anomaly scores
588. ML model audit by ensemble agreement
589. ML model audit by calibration curves
590. ML model audit by lift charts
591. ML model audit by precision/recall
592. ML model audit by ROC-AUC
593. ML model audit by F1-score
594. ML model audit by confusion matrix
595. ML model audit by feature contributions
596. ML model audit by SHAP values
597. ML model audit by LIME explanations
598. ML model audit by counterfactuals
599. ML model audit by adversarial examples
600. ML model audit by human judgments

---

## Phase 5: Deployment Notes (601-600+)

### 601-610: Tech Stack
601. Deploy on Render (free tier Python 3.11 Flask)
602. Use gunicorn for production server
603. SQLite for dev/local (free)
604. PostgreSQL for production (Render add-on)
605. Redis for caching (optional, add-on)
606. Cloudflare Workers for edge URL scanning (free tier)
607. GitHub Actions for auto-deploy on push
608. GitHub Secrets for API keys (Google Safe Browsing, etc.)
609. No database logging of personal identifiers (GDPR/MCMC)
610. Environment variables via Render dashboard (not committed)

### 611-620: Monitoring & Ops
611. Health check ping from external monitor
612. Set up Render alerting on downtime
613. Set up rate-limit exceeded alert
614. Set up moderation queue backlog alert (>100 pending)
615. Set up score computation failure alert
616. Set up feed refresh failure alert
617. Set up DB backup monitor
618. Set up disk space monitor
619. Set up request latency monitor
620. Set up error rate monitor

### 621-630: False-Positive Safeguards
621. NEVER auto-blacklist a number based on range alone
622. NEVER auto-score 013/014/015 without behavioral evidence
623. Score decay applied every 24h to prevent permanent flagging
624. Whitelist mechanism for legit businesses
625. Appeal mechanism (users can submit evidence)
626. Manual moderation override (can clear any flag)
627. Community counter-report ("This number is LEGIT, not a scam")
628. Trust weighting (verified reporters override anon)
629. Confidence interval shown to users (e.g., “75% confident”)
630. Clear disclaimer: “Risk score, not legal verdict.”

### 631-638: Final Validation
631. Test with known scam numbers (from MCMC press releases)
632. Test with known legit numbers (banks, hospitals)
633. Test with edge-case prefixes
634. Test with international numbers
635. Test with recycled/prepaid numbers
636. Test with VoIP numbers
637. Test with premium-rate numbers
638. Publish transparency report
