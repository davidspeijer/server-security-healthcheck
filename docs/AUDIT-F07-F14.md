# Oplevering F07–F14

Deze ronde wijzigt uitsluitend de parsers/checks voor F07–F14. Productieconfiguratie,
services, logs en databases zijn niet gewijzigd. Er is niets gecommit of gepusht.
Het installeren is niet uitgevoerd; `install.sh` krijgt alleen de noodzakelijke
kopieerregel voor de nieuwe runtimehelper. F01–F06 en `lmd_scanner.py` blijven
functioneel behouden en hun bestaande regressies draaien mee.

## Bevindingen, oplossingen en regressies

Alle nieuwe tests staan in [test_audit_round2.py](../tests/test_audit_round2.py).
De bestaande suite behoudt haar 253 tests; alleen fixtures/mocks zijn aangepast
voor expliciete auditbronnen, stdin-transport en correct gequote systemd-executables.

| ID | Root cause → gekozen oplossing en impact | Runtimebestanden | Nieuwe tests |
|---|---|---|---:|
| F07 | Grep selecteerde de laatste succesachtige regel zonder poging/tijdvalidatie. Een begrensde parser correleert starts, database-uitkomsten, completion en failures; interleaving en ongeldige/toekomstige tijd worden UNKNOWN. Een tussenmelding of oudere succesvolle poging kan een latere failure niet maskeren. | `clamav.sh`, `health_data.py` | 18 |
| F08 | Het nieuwste bestand uit vier directories kon actieve daily maskeren. Directoryselectie gebruikt clamd-unit/config en zo nodig het build-default; daily/main worden afzonderlijk gecontroleerd. Een recente bytecode of ongebruikte directory kan niet gezond verklaren. | `clamav.sh`, `health_data.py`, `common.sh` | 18 |
| F09 | Ontbrekende/read-failures werden nul; grep/sed was geen JSON-parser en had geen tijdsbovengrens. JSONL wordt strikt gelezen; failures geven geen telling en de caller meldt ERROR/UNKNOWN. | `common.sh`, `lmd.sh`, `health_data.py` | 17 |
| F10 | Ongeldige records werden overgeslagen en `sort -u -k6,6` verloor mount-identiteit/informatie. Alle df-records worden gevalideerd en volledige mountnamen bewaren het hoogste percentage. Onbruikbare output geeft ERROR. | `disk.sh` | 18 |
| F11 | Herkende fragmenten werden binnen onbekende controlflow geaccepteerd. Alleen twee volledige, expliciete scriptcontracten worden herkend; onbekende wrappers/controlflow worden UNKNOWN. De scripts worden nooit uitgevoerd. | `lmd_policy.sh`, `health_data.py` | 21 |
| F12 | Directives moesten op kolom nul beginnen; inline overrides/resets werden onvoldoende geïnterpreteerd. Een begrensde systemd-parser verwerkt whitespace, directivevolgorde, resets, files en continuations; ambiguïteit wordt UNKNOWN. | `lmd_policy.sh`, `health_data.py` | 26 |
| F13 | De eerste ontbrekende dependency retourneerde uit heel LMD. Monitor-dependencies worden verzameld; onafhankelijke subchecks gaan door. Coverage/native scratch-dependencies worden alleen bij hun eigen subcheck vereist. ERROR en malware-CRITICAL blijven samen zichtbaar. | `lmd.sh`, `lmd_policy.sh` | 13 |
| F14 | De curl-URL bevatte het token in argv en tracing kon credential-loading tonen. Config wordt via stdin geschreven, met literal escaping, geen tempfile en geredigeerde fouten; laden/verzenden schakelen tracing tijdelijk uit. | `telegram.sh`, `common.sh` | 14 |

Daarnaast zijn er **8 afzonderlijke integratiescenario’s A–H**. Totaal:
**153 nieuwe tests, 406 tests inclusief de bestaande 253**. F13 test zowel legacy
als native scans en de echte entrypoint-exitcode; F14 gebruikt ook een werkelijk
mock-subproces om argv en stdin afzonderlijk te inspecteren.

## Exacte freshness- en databasecriteria

FreshClam leest alleen `journalctl -o short-iso --since '7 days ago'` voor de
geconfigureerde daemon/oneshot. Er worden geen fysieke of geroteerde logbestanden
gelezen. Een commandfailure of lege/ongeldige journalbron kan geen geldig epoch
opleveren. Relevante regels moeten een herkenbare FreshClam-origin hebben.

Een ondersteunde poging begint met `ClamAV update process started`. Daarna is
completion aantoonbaar wanneer alle drie componenten `daily`, `main`, `bytecode`
een `NAME.cvd/cld updated (...)` of `NAME.cvd/cld database is up-to-date (...)`
hebben, of wanneer de begonnen poging de expliciete regel
`Database update completed successfully.` heeft. `Database test passed` is een
tussenstap: geen completion, ook niet als die regel de laatste observatie is.

Een latere terminale failure (`ERROR:`, database-update/testfailure, terminated
update), of een nieuwe incomplete poging, trekt eerdere completion in. Na een
failure kan een nieuwe complete poging herstellen. Afzonderlijke processen mogen
geen componenten tot één schijnbaar complete poging samenvoegen; overlap of
interleaving wordt UNKNOWN. Relevante events moeten chronologisch geordend zijn.
De parser ondersteunt de gebruikelijke officiële drie-componentenlayout; custom
of bytecode-disabled pogingen zonder expliciete completion blijven UNKNOWN.

Timezone-qualified ISO-tijden worden naar epoch geconverteerd. De tijdsbovengrens
is strikt `now`: **geen toegestane toekomstige clock skew**. Ongeldige tijden,
negatieve epochs en toekomst (ook fractioneel) worden verworpen. Leeftijd wordt
nooit als negatieve gezonde waarde getoond. Database-mtime gebruikt dezelfde
strikte toekomstregel via de bestaande `hc_file_age_hours`.

De actieve clamd-config wordt bepaald uit de geselecteerde unit/drop-ins:
ondersteund zijn `/usr/sbin/clamd`, `/usr/bin/clamd`, `/usr/local/sbin/clamd` met
precies `-c CONFIG` of `--config-file CONFIG`; `%i` wordt met de unit-instance
vervangen. Onbekende command/layout- of namespace/environment-overrides worden
UNKNOWN. `CLAMAV_CONFIG_FILE` is een expliciete bronselectie door de beheerder;
houd die gelijk aan de daadwerkelijke clamd-config.

De config moet leesbaar zijn. Eén literal, absoluut `DatabaseDirectory` is geldig;
malformed/duplicate directives en `Example`/includes worden verworpen. Wanneer de
directive ontbreekt, wordt het compile-default gelezen uit de stdout van het
geïnstalleerde `clamconf -g clamd.conf` of de packagingnaam `clamd.d/scan.conf`.
Er wordt geen configuratiebestand gegenereerd/geschreven. Op deze server werd
read-only `/etc/clamd.d/scan.conf` → `/var/lib/clamav` bevestigd.

`daily` en `main` zijn vereist, als `.cvd` of `.cld`. Elke aanwezige variant moet
regular, leesbaar, niet leeg en niet toekomstig zijn. Daily gebruikt
`CLAM_SIG_MAX_AGE_HOURS`; main krijgt een onafhankelijke timestamp/presence-check
maar geen daily-agegrens, omdat main weinig nieuwe releases krijgt. Bytecode is
optioneel. Beide formats tegelijk worden conservatief beide beoordeeld; een
recente variant maskeert geen stale andere variant. Tijdelijke namen zoals
`daily.cvd.tmp` tellen niet mee. Dit is freshness/presence, geen cryptografische
validatie van volledige database-inhoud of bewijs dat clamd reeds heeft herladen.

De logsemantiek volgt de [FreshClam-broncode](https://github.com/Cisco-Talos/clamav/blob/main/freshclam/freshclam.c);
config/default- en directorysemantiek volgen de [ClamAV-configdocumentatie](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamd.conf.5.in).

## Audit en disk

Audit is JSON Lines: iedere niet-lege regel moet een object bevatten met string
`type` en een geldige timezone-qualified ISO `ts`. Lege regels zijn toegestaan.
Duplicate JSON-keys, niet-standaard constanten, malformed records/timestamps,
read-failures of parser/dependencyfailures maken de hele telling ongeldig;
stdout levert dan **geen nul**. De caller geeft `ERROR ... event counts UNKNOWN`.
Een geldige lege bron of bron zonder passende events levert wel `0`.

Selectie is inclusief `[now - hours*3600, now]`. Oudere geldige events tellen niet;
toekomstige events geven parsefailure, ook tussen anders geldige records. Er wordt
geen grep-pipelinefailure meer verborgen. Een afwezige defaultbron is alleen
optioneel als `LMD_AUDIT` niet expliciet werd gezet; een expliciet geselecteerde
ontbrekende bron is ERROR.

Disk gebruikt `LC_ALL=C df -P -h -- PATHS`. `DISK_PATHS` blijft de bestaande
whitespace-separated configuratielijst; deze ronde voegt geen nieuw lijstformaat
toe. Er worden geen mounts op naam uitgesloten. Header, filesystem, human-readable
size/used/available, percent met `%`, en absolute mountnaam worden gevalideerd.
Lege output, commandfailure, malformed records of geen bruikbare records geven
ERROR. Geldige records blijven wel worden beoordeeld naast malformed records.

Een begrensde record-regex bewaart de volledige mountnaam vanaf `/`, inclusief
interne en afsluitende spaties;
deduplicatie gebruikt die volledige identiteit. Per mount blijft de hoogste
percentagewaarde met zijn available-waarde bewaard, onafhankelijk van recordvolgorde.
`pct >= DISK_WARN_PERCENT` waarschuwt; de threshold moet een positief decimaal getal
van maximaal 100 zijn. Mountnamen met een gedeelde prefix worden niet samengevoegd.

## Exact LMD-policycontract en systemd

Het minimale volledige contract staat letterlijk in `_lmd_daily_contract` in
[lmd_policy.sh](../lib/checks/lmd_policy.sh): `inspath`, `intcnf`, guarded internal
source, guarded base met nested compat-source, sysconfig/default-if/elif,
guarded cron-custom-config, gevolgd door precies één update-versieblok en één
signatureblok. De twee updatercalls zijn exact `maldet -d/-u 1 2>&1 | tail -20 >>
"$maldet_log"`, direct onder hun eigen `autoupdate_* == 1`-guard.

De tweede toegestane vorm staat volledig als `DAILY_STOCK_2_0_1`-data in
[health_data.py](../lib/checks/health_data.py): de hier read-only onderzochte
complete LMD 2.0.1 daily-layout, inclusief de exacte flock-recursie, fatale
missing-configbranches, defaults, pruning/sleep, update-failurediagnostiek,
maintenance/digest, platformscanbranches en custom-exec guard. Alleen de literal
`inspath` wordt aan `LMD_DIR` aangepast voor vergelijking. Beide vormen moeten
`bash -n` doorstaan. Blank lines, whole-line comments en leading/trailing
whitespace worden genegeerd; overige syntax, quoting, controlflow en statements
moeten volledig overeenkomen. De healthcheck bouwt geen Bash-interpreter en voert
geen van deze scripts uit. Alle andere vormen worden UNKNOWN. Bestaande checks
voor padbindings, overlays, custom commands en DTC-review blijven actief.

Systemd-unit/drop-intekst komt uit `systemctl cat` tijdens de healthcheck, zonder
sourcing. Leading whitespace/tabs en whitespace rond `=` worden herkend.
Continuation-backslashes verbinden regels met één spatie; tussenliggende comments
worden overgeslagen. Unsupported C-escapes/specifiers en unfinished continuations
worden UNKNOWN. Alleen whole-word literal quoting wordt ondersteund.

`Environment=` is last-value-wins en een lege assignment reset alle inline values.
`EnvironmentFile=` heeft een geordende lijst met resets; bestanden overschrijven
inline values, en latere bestanden winnen. Ondersteund zijn letterlijk
`/etc/sysconfig/maldet` en `/etc/default/maldet`, met optionele `-` en de bestaande
inspectiepad-overrides. Alleen ontbrekende optionele files mogen worden overgeslagen;
readfailures of unsupported assignmentsyntax maken het UNKNOWN. `export` is geen
ondersteunde systemd-fileassignment. `ExecStart=` moet na eventuele resets één
command zijn: maldet met `--monitor ${MONITOR_MODE}` of `$MONITOR_MODE`; executable
paths met spaties moeten gequote zijn. Een onbraced argument met whitespace in de
waarde is UNKNOWN wegens mogelijke wordsplitting. Afwezig/leeg betekent de
bestaande `default_monitor_mode`-fallback in de runtimecontext.

Manager-provided `MONITOR_MODE` zonder bewezen override is UNKNOWN.
`UnsetEnvironment` wordt als laatste stap toegepast, na commandexpansie. Een
relevante unset wordt daarom UNKNOWN in plaats van een gegokte fallback.
Deze volgorde volgt [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml);
whitespace/continuations volgen [systemd.syntax](https://github.com/systemd/systemd/blob/main/man/systemd.syntax.xml).

## Dependencies en Telegram

Ontbrekende `systemctl`/`pgrep` leveren elk eenmaal een monitor-ERROR. De afhankelijke
monitorchecks worden overgeslagen; policy, audit, signature/program-updater,
coverage en legacy/native fullscans gaan onafhankelijk door. `rmdir` is alleen
vereist voor de subchecks die hun eigen scratchdirectory moeten kunnen opruimen;
een legacy-only fullscan heeft die dependency niet. ERROR en CRITICAL worden
samen verzameld en de bestaande uiteindelijke ERROR-exitcode **2** blijft gelden.

Telegram gebruikt `curl --config - -fsS --max-time 20 -X POST`. URL, token, chat ID
en escaped bericht worden door Bash builtins via stdin geschreven. Geen secret
wordt als curl-argvargument of extra exported environment doorgegeven, en er is
geen credential-tempfile. Het token moet `digits:URL-safe-characters` zijn; chat
is numeriek (eventueel negatief) of een `@username`. Curl stdout/stderr wordt
onderdrukt; failures geven alleen een generieke transportmelding. Beide openbare
load/sendfuncties schakelen xtrace uit vóór verwerking en herstellen de vorige
tracingstatus. Tests controleren argv, stdin, stdout, stderr, failures, tracing,
escaping, truncation en een echt offline mock-subproces. Dit beschermt het eigen
codepad; het kan een door de gebruiker zelf buiten dit codepad getraceerde secret-
assignment niet terugnemen. Curl 7.61.1 ondersteunt de gebruikte stdin-config.

F20 (`ok:false` in HTTP-success responsebody) is niet geïmplementeerd.

## Compatibiliteit en scope

Runtime is Bash 4+ en Python **3.6.8**, uitsluitend stdlib; tests gebruiken Python
**3.12.15**. De nieuwe helper wordt door de bestaande installer meegekopieerd,
zonder andere installer-refactor. Python/helper-absence kan geen parser-PASS geven.
Semantisch equivalente maar niet ondersteunde policy/unit/FreshClam-layouts kunnen
voortaan UNKNOWN geven. Expliciet geselecteerde ontbrekende auditbronnen zijn
voortaan ERROR. Geldige bestaande configured thresholds/updater/service/scan-
semantiek blijven behouden; Telegram fake placeholders moeten syntactisch geldig
zijn in tests, terwijl bestaande echte credentials geen migratie nodig hebben.

Nieuwe bevindingen buiten scope: geen nieuw onafhankelijk probleem bevestigd.
Bewust niet gewijzigd: F15–F22, live service/config/package/firewall/cron/DirectAdmin-
beheer, database-updates, quarantaine, malware/scanner-classificatie F01–F06,
service-autodiscovery, response-bodyinterpretatie, commits en pushes.

## Verificatie

- `python3.12 -m unittest discover -s tests -v`: **406 tests, OK, 46.055s**.
- **153 nieuw**: F07 18, F08 18, F09 17, F10 18, F11 21, F12 26,
  F13 13, F14 14, plus 8 integratiescenario’s.
- `git diff --check`: geslaagd, geen output.
- `bash -n`: geslaagd voor alle **13** entrypoint/install/uninstall/lib/check/notify
  shellbestanden, elk afzonderlijk gecontroleerd.
- Python 3.6.8: beide runtime-Pythonbestanden via `ast.parse` gecontroleerd;
  de nieuwe helper daadwerkelijk geïmporteerd/uitgevoerd met timezoneconversie,
  full-stockcontractherkenning en read-only directoryresolutie.
- Bash 4.4.20 en curl 7.61.1 zijn de aangetroffen productieversies.
- ShellCheck ontbreekt; niet geïnstalleerd.
- `git diff` inhoudelijk gecontroleerd; nieuwe bestanden afzonderlijk beoordeeld.
- De suite gebruikt offline fixtures/mocks en tijdelijke testbestanden. Er zijn
  geen echte installatie-, package-, verwijder- of systemctl-acties uitgevoerd.

`git diff --stat` (Git telt nog niet toegevoegde bestanden hier niet mee):

```text
 README.md                       |  75 +++++++++++++++++++++++-----
 config/healthcheck.conf.example |   3 ++
 docs/LMD-PARSING.md             |  28 +++++++----
 install.sh                      |   3 ++
 lib/checks/clamav.sh            | 105 +++++++++++++++++++++++++--------------
 lib/checks/disk.sh              |  56 +++++++++++++++------
 lib/checks/lmd.sh               |  24 ++++++---
 lib/checks/lmd_policy.sh        | 106 ++++++++++++++++------------------------
 lib/common.sh                   |  44 +++++++++--------
 lib/notify/telegram.sh          |  44 ++++++++++-------
 tests/test_healthcheck.py       |  21 ++++----
 11 files changed, 312 insertions(+), 197 deletions(-)
```

Nieuwe, nog niet toegevoegde bestanden: `health_data.py` (500 regels),
`test_audit_round2.py` (498 regels), en dit opleverrapport. Er zijn dus **14 gewijzigde/
nieuwe projectbestanden**: 11 tracked wijzigingen en 3 untracked toevoegingen.
Geen staged wijzigingen, commit of push.

`git status --short`:

```text
 M README.md
 M config/healthcheck.conf.example
 M docs/LMD-PARSING.md
 M install.sh
 M lib/checks/clamav.sh
 M lib/checks/disk.sh
 M lib/checks/lmd.sh
 M lib/checks/lmd_policy.sh
 M lib/common.sh
 M lib/notify/telegram.sh
 M tests/test_healthcheck.py
?? docs/AUDIT-F07-F14.md
?? lib/checks/health_data.py
?? tests/test_audit_round2.py
```


## Vervolg F15–F22

Dit document beschrijft de afgeronde F07–F14-ronde. Vanaf v0.5.3 controleert
Telegram bovendien de JSON-response; de eerdere transport-only beperking is
opgelost. Bestandslezers zijn begrensd en scanneranalyse gebruikt batchsnapshots.
Zie [AUDIT-F15-F22.md](AUDIT-F15-F22.md) voor de actuele installatie-, discovery-,
resource- en presentatiecontracten. De hier beschreven securitysemantiek blijft
behouden; de nieuwe ronde vervangt het toenmalige installatiemechanisme.
