# Audit F15–F22 — oplevering v0.5.3

Datum: 2026-10-11. Werkgebied: `/opt/server-security-healthcheck`.
Productie is uitsluitend read-only bekeken voor omvangmetingen. Geen installatie,
package manager, echte systemctl/curl-aanroep, restart, commit of push uitgevoerd.
Installer-, service- en Telegram-tests gebruiken geïsoleerde fixtures en mocks.
F01–F14 blijven beschermd door de bestaande 406 tests.

## Per bevinding

| ID | Root cause | Oplossing en impact | Bestanden / tests |
| --- | --- | --- | --- |
| F15 | Onbegrensde tekst/gzip-lezers en onvoldoende bescherming tegen speciale bestanden | Gemeenschappelijke reguliere-bestandslezing, nonblocking open, fstat, byte/regel/record/tijdbudgetten; privé snapshots vóór Bash-parsing. Onbetrouwbare input geeft ERROR/UNKNOWN en geen herstelbewijs. | `bounded_input.py`, `health_data.py`, `lmd_scanner.py`, `lmd.sh`, `lmd_policy.sh`, `clamav.sh`, `common.sh`; ResourceTests en integratie A/C |
| F16 | Dezelfde rotaties werden per scan geopend/decomprimeerd; elk metadata-veld startte awk | Eén scanner-batchsnapshot per fullscancheck, onafhankelijke intervalanalyse; metadata-maps met lokale levensduur in de parent shell. Geen cache tussen runs. | `lmd_scanner.py`, `lmd.sh`; BatchTests en integratie B |
| F17 | Runtime werd bestand voor bestand overschreven, zonder ownershipbewijs voor obsolete modules | Volledige staged release, verplichte bestanden en syntaxcontrole, atomische actieve symlink, launcher die één release pint; oud manifest bepaalt welke obsolete bestanden niet meegaan. | `install.sh`, `runtime.manifest`, entrypoint; InstallerTests |
| F18 | Sommige lifecycle-tests isoleren scannerreliability met een clean mock; DST-fixture ontbrak een geldige invocation | Gerichte echte parser/batch/resource-tests, echte LMD+disk entrypoint-integratie, causale DST-controledag en expliciete Python 3.6-check. Bestaande isolatiemocks worden als zodanig gedocumenteerd. | Alle drie bestaande testmodules plus `test_audit_round3.py`; integratie G/H |
| F19 | Ruwe waarden werden als console/detail/notification-tekst afgedrukt | Centrale `hc_present` op status/detail/log-boundaries en directe hit-/coverage-details. Controltekens worden zichtbaar geescaped; classificatie ontvangt originele waarden. NUL in shell-bound records wordt geweigerd. | `common.sh`, `lmd.sh`, entrypoint, Telegram; PresentationTests en integratie D |
| F20 | curl exit 0 werd als API-succes beschouwd | Transport én strict JSON-object met boolean `ok: true`; maximaal 64 KiB response, geen raw response/error-description logging. Pipeline controleert transportstatus ook zonder caller-pipefail. | `telegram.sh`, `health_data.py`; TelegramTests, bestaande F14-tests, integratie E/G/H |
| F21 | Mislukte systemctl cat en afwezige service werden gelijk behandeld | PRESENT / NOT_APPLICABLE / DISCOVERY_FAILED; geldige unitlisting of bekend executable nodig. Failed/malformed discovery geeft ERROR; compacte samenvatting toont aantallen. | `common.sh`, `lmd.sh`, entrypoint; DiscoveryTests, ServiceModuleTests, integratie F/H |
| F22 | Release-, runtime- en severityteksten beschreven achterhaald gedrag | README, CHANGELOG, beide LMD-documenten en F07–F14-rapport afgestemd op v0.5.3, huidige helpers, installatie en exit/severitycontract. | Versie-entrypoint, genoemde documentatie, dit rapport |

## Bronnen en resource-limits

`bounded_input.lines` controleert eerst het gevolgde symlink-target en opent met
`O_RDONLY|O_NONBLOCK`. Daarna controleert fstat het daadwerkelijk geopende
bestand. Een omwisseling naar FIFO tussen stat/open kan daardoor niet onbeperkt
blokkeren. FIFO, socket, character/block-device en directory zijn geen loginput.
Symlinks naar reguliere bestanden blijven toegestaan. UTF-8 moet geldig zijn.
Gzip wordt via dezelfde geopende descriptor gelezen, met begrensde readline.

| Budget | Default | Instelbaar in vertrouwde omgeving |
| --- | --- | --- |
| Fysieke bestandsgrootte | 64 MiB | `SSHC_MAX_FILE_BYTES` |
| Gedecomprimeerde bestandsgrootte | 128 MiB | `SSHC_MAX_EXPANDED_BYTES` |
| Gezamenlijke scanner-/metadata-snapshot | 128 MiB | dezelfde expanded-override |
| Regel inclusief newline | 64 KiB UTF-8 bytes | `SSHC_MAX_RECORD_BYTES` |
| Records per bestand | 1.000.000 | `SSHC_MAX_RECORDS` |
| Python invocation / Bash parsing scope | 20 s | `SSHC_READ_SECONDS` |
| Telegram-response | 64 KiB | vaste limiet |

Overrides moeten positieve integers zijn. Ze zijn geen healthcheck.conf-keys.
De Python CLI heeft een SIGALRM-budget voor de gehele parsercall; daarnaast
controleert de lezer monotone tijd tussen records. Een dedicated BudgetExceeded
exception verlaat de hele batch en wordt niet als een intervalfout ingeslikt.
Bash controleert elapsed budgetten in configuratie-, compat-, cron-, metadata-,
selectie-, native-index- en hitloops. Native processingtimeout stopt vóór de
selector; partial adapters worden niet als complete input behandeld. Dit is geen globale timeout
voor alle Bash-checks, systemd/journalctl of andere externe commando's samen.
Regel-, record- en volumebudgetten begrenzen de hoeveelheid doorgegeven data.

Read-only productie-inventarisatie:

- LMD logs: 23 reguliere bestanden, circa 12,67 MB totaal; grootste bestand
  `inotify_log` circa 9,88 MB (wordt niet door de scannerparser gelezen).
- Scannerbronnen: 6 bestanden; grootste fysieke bron 167.991 bytes.
- Eén begrensde leespassage: 1.526.157 expanded bytes, 10.865 records;
  grootste scannerrecord 232 bytes.
- Sess-directory: 39 bestanden, circa 38,66 MB totaal; grootste bestand
  `monitor.scanned.hist` circa 38,64 MB (geen native/lifecycle parserbron).
- `session.index`: 1.454 bytes; grootste relevante TSV: 573 bytes;
  huidige lifecyclebestanden: 432 bytes. Auditbron: 4.121 bytes.

De aggregate scannerlimiet is circa 88 keer de gemeten expanded historie;
regelbudget circa 282 keer de grootste gemeten regel. Er zijn dus ruime marges.
Geen zware productiebenchmark of grote DoS-fixtures gebruikt.

| Bron | Leespad na wijziging | Foutgedrag |
| --- | --- | --- |
| Scannerrotaties, inclusief gzip | bounded lines → gedeelde immutable snapshot → intervalanalyse | scanner UNKNOWN/CRITICAL |
| Historische lifecycleproofs | bounded lines in Python | geen proof bij lees-/parsefailure |
| Native index, lifecycle, TSV | bounded private directorysnapshot vóór oorspronkelijke selector | snapshotfailure ERROR/UNKNOWN, fullscan-classificatie stopt |
| Externe session_file-details | bounded tekst vóór header/hitparsing | ERROR/UNKNOWN of bestaande unclassified CRITICAL |
| Audit JSONL | bounded UTF-8 tekst → strict JSON/timestamps | ERROR met UNKNOWN counts |
| Main/LMD/environment/compat/cron/ClamAV config | bounded tekst vóór bestaande literal parsers | ERROR bij main config; policy UNKNOWN/WARNING of ClamAV ERROR |
| Daily-script | bounded tekst → bash-n op tekst → exact contract; nooit uitvoeren | UNKNOWN/WARNING |
| Webrootlijst | bounded tekst → privé regulier snapshot voor setvergelijking | ERROR/UNKNOWN |
| Eventlog/signatureversie | bounded tekst; updaterpatronen blijven ongewijzigd | UNKNOWN/WARNING of signatureversie ERROR |
| Helper stdin / FreshClam journal | byte/record/count-bounded tekst, CLI alarm; journal direct gepiped | caller rapporteert parserfailure |

Een metadata-snapshotfailure geeft geen gedeeltelijke fullscan-PASS. Andere LMD
checks en andere modules blijven onafhankelijk uitgevoerd worden. TSV is een
regelgebaseerd formaat: embedded newlines zijn malformed records, geen geldige
multiline-signatures. Positieve malformed hitcounts blijven unclassified/CRITICAL
op de bestaande valide lees-/selectiepaden.

## Scannerarchitectuur en performance

De bestaande `result`-intervalanalyse blijft de classifier. `batch` leest logs
één keer en geeft iedere intervalanalyse dezelfde snapshot. Start/end markers,
host, invocation, access counters, overlaps, relevante rotatiegaten en recovery
blijven per interval lokaal. Kalendercorruptie buiten een bewezen irrelevant
interval volgt de bestaande policy. Een corrupt gecomprimeerd bestand verhindert
batchoutput: alle afhankelijke Bash-results worden UNKNOWN. Er wordt pas output
gegeven nadat de volledige batch opgebouwd is.

Caches bestaan uitsluitend als dynamically scoped Bash locals. Geen persistente
resultcache, bestand in een productiedirectory of cross-run state. De oorspronkelijke
session-directory blijft beschikbaar voor onafhankelijke historical-finished
proofs; tijdelijke native adapters veranderen die provenance niet.

Gemeten vóór/na op exact dezelfde kleine, representatieve fixtures:

| Fixture / instrumentatie | Voor | Na |
| --- | --- | --- |
| Twee voltooide relevante scans: werkelijke scanner-helperstarts | 2 | 1 |
| Dezelfde fixture: metadata awk-helperstarts | 39 | 0 |
| Dezelfde fixture: extra bounded metadata snapshot-helper | 0 | 1 |
| Dezelfde fixture: clean scannerresultaten | 2 | 2 |
| Acht intervallen, acht gzip-rotaties: logopens | 64 | 8 |
| Acht intervallen, acht gzip-rotaties: decompressies | 64 | 8 |
| Gemeten in-process parserfixtureduur | 0,11858 s | 0,05326 s |

Voor de processmeting is HEAD-code in een geïsoleerde repo-temporary tree geladen;
Bash-wrappers telden werkelijke scannerstarts en metadata-awkstarts en delegeerden
naar de echte tools. Voor logopens telde een wraps-mock `lines` zonder de echte
lezer te vervangen. De batchresultaten zijn met individuele results vergeleken.
De tijdmeting is één lokale fixturemeting, geen gegarandeerde productiespeedup.
Bash command substitutions bestaan nog; native recordchecks gebruiken hun bestaande
awk/date-processen waar nodig. De claim van 0 hierboven betreft metadata-field
awkstarts in de gemeten legacy selectorfixture, niet alle subprocessen wereldwijd.

## Installatie, ownership en failure-semantiek

De installer vereist root. Een release wordt voorbereid onder
`/usr/local/lib/.server-security-healthcheck-releases/release.*`, op hetzelfde
filesystem als `/usr/local/lib/server-security-healthcheck`. Staging begint
privé (0700); de gevalideerde release wordt voor activatie 0755. Runtime libraries
zijn 0644, entrypoint/launcher 0755, Telegram-example/new active config 0600.
Actieve bestaande configs en hun permissions/symlinks blijven ongemoeid.
Shipped installbestanden worden door de root-installer gemaakt; custom kopieën
gebruiken `cp -a` en behouden hun metadata. Geen nieuwe production-installatie
is uitgevoerd om ownership op deze server te wijzigen.

`runtime.manifest` is expliciet ownershipbewijs voor shipped libraries. Verplichte
built-ins en Pythonhelpers worden gecontroleerd, alle staged shellfiles met bash-n
en helpers met de runtime-Python AST-parser. De launcher pint de gekozen release
vóór exec, zodat zijn entrypoint en library samen horen. De entrypoint resolveert
LIB_DIR bovendien naar een fysiek releasepad vóór het laden van modules.

Bij upgrade wordt een oud manifest-owned obsolete bestand niet naar de nieuwe
release gekopieerd. Het blijft beschikbaar in het rollbackarchief, maar wordt niet
meer door de actieve glob geladen. Onbekende/custom bestanden en companion-files/directories worden bewaard, ook
buiten checks/notify. De nieuwe launcher is al staged voordat oude rootbestanden
worden gekopieerd; een oude launcher-symlink kan geen schrijftarget introduceren.
Zonder oud manifest kan een onbekend oud bestand niet bewezen project-owned zijn;
het blijft staan voor handmatige review. Configbestanden zijn geen runtime-manifest
onderdeel en worden niet verwijderd of overschreven.

Failure vóór activatie (ontbrekend bestand, syntax, staging-copy, unit-copy,
SIGTERM tijdens staging) geeft nonzero en laat de oude actieve release intact.
Een incomplete/orphan stagingtree heeft geen invloed op de actieve runtime.
Fresh/subsequent symlinkactivatie is atomisch. Eenmalige conversie van de oude
real-directory layout gebruikt een backup-rename met herstel bij afgehandelde
pre-activation failure. SIGKILL/power loss in het korte rename/switch-gat kan
handmatig herstel van de `.previous.*` directory vereisen; geen crash-transaction
wordt geclaimd. Traps herstellen ook een switch die net vóór ACTIVATED onderbroken
werd. Na activatie blijft de gevalideerde runtime actief bij een volgende fout;
het script meldt expliciet failure en adviseert opnieuw installeren.

Unit- en examplebestanden worden afzonderlijk vernieuwd vóór runtimeactivatie;
ze horen niet bij één runtime-pointertransaction. systemctl daemon-reload blijft
een installeractie, in tests uitsluitend gemockt. De timer wordt niet gestart.
Oude releases/backups worden bewust niet automatisch gepruned. Uninstall verwijdert
de actieve pointer/launcher en units, bewaart config en laat archieven voor
handmatige cleanup staan omdat daarin custom bestanden kunnen zitten.

## Testarchitectuur en dekking

De 406 bestaande tests blijven aanwezig. Contractwijzigingen aan bestaande tests:

- Telegram-successmocks leveren nu `{"ok":true}` in plaats van een lege/requestbody.
  Token/argv/xtrace/redactionassertions zijn behouden, niet afgezwakt.
- De readfailure-mock grijpt nu aan op `bounded_input.os.open`, de werkelijke
  descriptor-opener, in plaats van het niet meer gebruikte builtins.open.
- Spec-importtests maken het naastgelegen helperdirectory expliciet importeerbaar.
- De systemctl-active-mock herkent nu de veilige `--` argumentseparator; de
  inactive-timerassertion is behouden.
- Versieassertion is v0.5.3. DST bevat een echte invocation plus gezonde controle
  op de voorafgaande dag; UNKNOWN kan niet meer door ontbrekende invocation slagen.

`HealthcheckTests.run_shell` houdt zijn bestaande clean reliability-mock voor
geïsoleerde lifecycle/config/hit-unittests. Die bewijzen geen scannerhealth. De
ScannerReliabilityTests, audit regressions, nieuwe BatchTests en integraties A/B/G/H
gebruiken de echte scanner. Nieuwe parsertests gebruiken stdlib en kleine budgets. Vijf ShellDeadlineTests
controleren configuration, metadata, selection, native en hit processingtimeout.
Projecthelpers schakelen bytecode-writing uit vóór import van bounded_input, zodat
runtime parsing geen cachebestanden in de geïnstalleerde library hoeft te schrijven.
Geen externe testframeworks of packages geïnstalleerd.

Alle shipped checks hebben gerichte dekking: disk, LMD, ClamAV/FreshClam en policy
via bestaande suites; Apache/Rspamd/PureFTP/Exim via service-/discoverytests. Exim
queue-success/failure heeft nu gerichte tests. Monitor-systemdstate, pgrep,
service-active, journaltransport, df-commandfailure en netwerktransport blijven
operationele mock-boundaries; er is geen live service/API-test. Parsers en
classifiercode achter die boundaries draaien echt. De Unix-socketbindtest wordt
expliciet geskipt als de sandbox bind weigert; device/FIFO/symlinkguards draaien wel.

Nieuwe tests: 115 afzonderlijke methoden, zonder inheritance die bestaande tests
verdubbelt. De socketcase is de enige environment-afhankelijke skip.

| Testgroep | Aantal |
| --- | ---: |
| ResourceTests | 19 |
| BatchTests | 9 |
| PresentationTests | 16 |
| TelegramTests | 14 |
| DiscoveryTests | 13 |
| ServiceModuleTests | 6 |
| InstallerTests | 18 |
| IntegrationTests | 8 |
| ShellDeadlineTests | 5 |
| DirectoryProbeTests | 3 |
| OptionalInputTests | 4 |
| Nieuwe totaal | 115 |
| Bestaand + nieuw | 521 |

Cross-cutting scenario's:

- A: scanner/metadata-budgetfailure geeft UNKNOWN/ERROR zonder PASS.
- B: shared rotaties, batch vs individuele semantic equality; echte Bash fullscan.
- C: incomplete stage en daadwerkelijke SIGTERM-stagingfailure behouden oude release.
- D: malicious newlinewaarde blijft één geescaped detailregel.
- E: Telegram ok:false geeft notificationfailure.
- F: failed discovery geeft ERROR, geen NOT_APPLICABLE.
- G: echte entrypoint met gezonde disk/LMD-parser en frozen fixtureclock, exit 0;
  aparte mock-API notificationtest succesvol zonder secrets. Monitor/configpolicy
  zijn in deze fixture bewust disabled; die hebben aparte gerichte tests.
- H: echte disk-WARNING, echte LMD malware-CRITICAL, auto-discovery-ERROR en API
  reject samen; alle findings blijven zichtbaar en eindstatus is 2.

## Presentatie, Telegram en discovery

`hc_present` behandelt status/detail/log en directe hit/coverage-values consequent:
LF → `\n`, CR → `\r`, TAB → `\t`, overige C0/DEL → `\xNN`. Veilige Unicode blijft
behouden. Raw waarden blijven beschikbaar voor EICAR/classificatie; een deceptive
signature met controlteken wordt niet ineens een allowlisted test-signature.
Bash kan NUL niet representeren: zulke source records worden zichtbaar geweigerd
vóór shellconsumptie; de scanner weigert NUL ook vóór invocationclassificatie. Telegram-structurele separators blijven gewone newlines.
Geen Markdown/HTML parse mode toegevoegd.

Telegram accepteert alleen een object met unieke JSON-keys en boolean `ok: true`.
Integer 1, array, lege body, malformed JSON, oversize en ok:false zijn failure.
Curl max-time is 20 s; HTTP/networkfailure blijft failure, ook met een ok:true body.
Responses worden expliciet als UTF-8 gedecodeerd, ook onder LC_ALL=C. Lange
berichten krijgen een conservatieve 3500-byte-prefix zonder gedeeltelijk UTF-8-teken,
plus de bestaande afkappingsmelding. Responsevalidatie is een directe pipe: geen onbeperkte Bash responsevariabele,
geen raw description logging. Token/chat worden via curl stdin-config verstuurd,
niet via child argv; deze code exporteert geen credentialvariabelen. Tracing wordt
vóór credentialhandelingen uitgeschakeld en daarna in de caller hersteld. Normale
healthy runs sturen niets. Notificationfailure houdt exit 2 en lokale findings.

Service auto-mode checkt executables en anders een geldige list-unit-files listing.
Bekende unit, ook disabled/masked: PRESENT, daarna gewone active-check. Succesvolle
lege listing: NOT_APPLICABLE. Missing systemctl, nonzero command of malformed
listing: DISCOVERY_FAILED/ERROR. Expliciete mode slaat auto-discovery over; disabled
mode voert de integratie niet uit. LMD gebruikt een stat-probe: alleen ENOENT betekent afwezig; permissionfailure,
broken symlink en een onbruikbaar path geven discoveryfailure. Optionele Telegram-
config en de default auditbron gebruiken dezelfde expliciete file-stateprincipes;
onleesbare of speciale bronnen worden niet stilzwijgend als afwezig behandeld.
Service-activechecks gebruiken een -- separator en onderdrukken ruwe diagnostics. De compacte summary telt invoked
checkfunctions, disabled built-ins, not_applicable en discovery_failed; invoked
checks kunnen ook not_applicable/failure blijken, de tellers zijn geen partitie.

## Compatibiliteit en bewust ongewijzigd

Runtime: Python 3.6.8 stdlib en Bash 4.4.20 op deze server; tests Python 3.12.15.
Python is nu ook nodig voor bounded main-configreading en Telegram-responsevalidatie.
Geen jq of pip-package toegevoegd. install-dependencies.sh had Python/coreutils
al in zijn packagecontract en is niet uitgevoerd of aangepast.

Exit 0 = geen findings/errors; exit 1 = WARNING/CRITICAL; exit 2 = execution/config/
parser/discovery/notification failure. ERROR wint de eind-exitcode van CRITICAL,
maar verbergt geen andere findings. Scanner UNKNOWN blijft CRITICAL; UNKNOWN is
geen afzonderlijke exitcode. Bestaande native/lifecycle validation, exact EICAR-
allowlist, strictly later completed clean recovery, tie-policy, retentionbeleid en
malware/quarantine-assessment zijn niet versoepeld. Geen scan/remediationproducent,
LMD-config, cron, DirectAdmin, productielog, package of systemd-state gewijzigd.

## Nieuwe bevindingen buiten scope

Geen nieuwe onafhankelijke bevinding opgelost. Resterende operationele grenzen
(geen globale timeout op externe servicecommands, handmatige oude-directory
crashrecovery, archived-release cleanup en geen live netwerk/service-test) zijn
hier expliciet als implementatielimiet beschreven; geen toekomstplan als feature
gepresenteerd. Unicode bidi/C1-formatting valt buiten de gevraagde C0/DEL-escaping.

## Verificatie

Volledige suite: `python3.12 -m unittest discover -s tests -v`:

```text
Ran 521 tests in 128.115s
OK (skipped=1)
```

406 bestaande + 115 nieuwe tests; 520 daadwerkelijk uitgevoerd, 1 expliciete
Unix-socketbindskip wegens sandbox-permissies. Geen failures of errors.
De eerdere volledige 520-test-run was eveneens groen; de uiteindelijke run omvat
ook de aanvullende UTF-8-truncatiecase. Log: `tmp-round3-release-verification.log`
(lokaal genegeerd testartifact, geen runtimebestand).

- Alle shipped shellfiles, entrypoint, install.sh, install-dependencies.sh en
  uninstall.sh: `bash -n` PASS onder Bash 4.4.20.
- Alle drie Python-runtimehelpers: compile(source, filename, 'exec') PASS onder
  echte Python 3.6.8, zonder bytecodebestanden te schrijven. UTF-8 Telegram JSON
  `ok:true` CLI-smoketest onder Python 3.6.8/LC_ALL=C PASS.
- Test runner Python 3.12.15. Entrypoint `--version`: v0.5.3.
- `git diff --check`: PASS. ShellCheck niet beschikbaar; niet geïnstalleerd.
- Geen productie-installatie, services/packagewijzigingen, commit of push.

Diffstat van de 17 gewijzigde tracked bestanden (Git telt de vier nieuwe,
nog untracked bestanden hieronder niet mee):

```text
CHANGELOG.md                     |  18 ++++
 README.md                        |  94 +++++++++++++++---
 bin/server-security-healthcheck  |  20 +++-
 docs/AUDIT-F07-F14.md            |  10 ++
 docs/LMD-NATIVE-INVESTIGATION.md |  26 +++++
 docs/LMD-PARSING.md              |  28 +++++-
 install.sh                       | 121 ++++++++++++++++++------
 lib/checks/clamav.sh             |  12 ++-
 lib/checks/health_data.py        |  70 ++++++++++++--
 lib/checks/lmd.sh                | 135 ++++++++++++++++++++++----
 lib/checks/lmd_policy.sh         |  37 ++++++--
 lib/checks/lmd_scanner.py        | 199 +++++++++++++++++++++++----------------
 lib/common.sh                    |  75 ++++++++++++---
 lib/notify/telegram.sh           |  15 +--
 tests/test_audit_regressions.py  |   2 +
 tests/test_audit_round2.py       |  10 +-
 tests/test_healthcheck.py        |  16 +++-
 17 files changed, 694 insertions(+), 194 deletions(-)
```

De vier nieuwe bestanden zijn dit rapport, `lib/checks/bounded_input.py`,
`runtime.manifest` en `tests/test_audit_round3.py`. Werkboomstatus bij oplevering:

```text
 M CHANGELOG.md
 M README.md
 M bin/server-security-healthcheck
 M docs/AUDIT-F07-F14.md
 M docs/LMD-NATIVE-INVESTIGATION.md
 M docs/LMD-PARSING.md
 M install.sh
 M lib/checks/clamav.sh
 M lib/checks/health_data.py
 M lib/checks/lmd.sh
 M lib/checks/lmd_policy.sh
 M lib/checks/lmd_scanner.py
 M lib/common.sh
 M lib/notify/telegram.sh
 M tests/test_audit_regressions.py
 M tests/test_audit_round2.py
 M tests/test_healthcheck.py
?? docs/AUDIT-F15-F22.md
?? lib/checks/bounded_input.py
?? runtime.manifest
?? tests/test_audit_round3.py
```
