# User API

The service binds to `127.0.0.1:8080` by default and has no web page. Java 17
or later, Maven, an SMTP service supporting authenticated STARTTLS, and a
cryptographically random JWT signing secret are required.

Set these environment variables before starting the application:

- `USER_MANAGER_JWT_SECRET`: a randomly generated secret of at least 32 bytes.
  Keep it outside source control; changing it invalidates issued access tokens.
- `USER_MANAGER_SMTP_HOST` and optionally `USER_MANAGER_SMTP_PORT` (default 587).
- `USER_MANAGER_SMTP_USERNAME` and `USER_MANAGER_SMTP_PASSWORD`: SMTP credentials.
- `USER_MANAGER_MAIL_FROM`: the sender address accepted by the SMTP provider.

Do not commit credentials. With the variables configured, run `mvn spring-boot:run`
from this directory. Live email delivery depends on the configured provider;
the automated tests use a fake sender.

## Account flow

All endpoints are under `/api/users` and accept JSON:

1. `POST /register` with `email` and `personalInfo` requests a verification
   code. The response is generic and the account cannot log in yet.
2. `POST /verify` with `email`, the emailed `code`, and a newly chosen
   `password` verifies ownership and sets the password. Choose the password
   after receiving the code; a prior registration request cannot choose it.
3. `POST /authenticate` with `email` and `password` returns an access token.
   `GET /{userId}` requires `Authorization: Bearer <token>` and only exposes
   the token's own account.
4. For recovery, `POST /password-reset/request` with `email`, then
   `POST /password-reset` with `email`, `newPassword`, and the emailed code in
   `resetToken`. A successful reset invalidates existing access tokens.

Verification and recovery codes are single-use, expire after 15 minutes, and
are sent at most once per minute per account and purpose. Neither code is
returned in the API response.

New passwords must be 12–128 characters. They are stored as salted
`bcrypt-sha256` hashes (bcrypt cost 12 with a SHA-256 prehash so passwords
longer than bcrypt's 72-byte input limit are not truncated). Existing PBKDF2
hashes are upgraded upon successful login; existing passwords shorter than
12 characters continue to work until changed.

Authentication is limited to five failed attempts per normalized email in a
15-minute window and 30 total attempts per client IP in a 15-minute window.
The next attempt returns HTTP 429 with `Retry-After`. A successful login
clears the account failure counter but not the IP counter. Counters persist in
the SQLite database and are shared by instances using the same database.
In-flight attempts count toward the five-attempt account limit until they
finish, so concurrent valid logins can temporarily receive HTTP 429. If a
process stops or verification fails unexpectedly, its reservation remains
until its 15-minute expiry. Successful logins clear recorded failures, but
not other in-flight reservations. Password checks run concurrently with a
per-manager limit based on the JVM's available processor count.
The IP is taken from the direct connection, not untrusted forwarding headers.
Behind a reverse proxy, all users therefore share the proxy's limit unless a
separately configured trusted-proxy solution is used; enforce appropriate
limits at the proxy. The account limit can be used to temporarily lock another
user out. SQLite's serialized writes also limit throughput; use a shared
rate-limiting service for a distributed deployment with separate databases.
API responses are JSON, not sanitized HTML: clients must encode personal
information for the context in which it is displayed.

## Security checks

Run the security profile from this directory:

```powershell
mvn -Psecurity verify
```

This runs the normal tests, SpotBugs with FindSecBugs, and OWASP
Dependency-Check. SpotBugs checks production bytecode and fails the build on
high-priority findings; its priority is not a CVSS severity rating. Review
all other findings in `target\spotbugsXml.xml` too. Dependency-Check generates
HTML and JSON reports in `target` and fails the build for detected CVSS scores
of 7 or higher or scanner errors. Unscored vulnerabilities, false positives,
missing advisories, configuration risks, and findings outside those scanners'
coverage require separate review. The .NET assembly analyzer is disabled for
this Java project, as is Sonatype OSS Index; the scan depends on the other
enabled advisory sources.

The first dependency scan downloads the NVD vulnerability database and may
take a long time. For improved NVD rate limits, optionally set `NVD_API_KEY`
as an environment variable before running the profile. Do not commit the key
or pass it on the command line. The scan requires network access to advisory
feeds; an unsuccessful or incomplete update is not a clean scan.

The attack simulations can be run separately with
`mvn "-Dtest=UserApiSecurityTest,UserManagerTest" test`. They cover selected
injection, authorization, token, reset-code, rate-limit and concurrency
scenarios, not a complete penetration test or OWASP assessment.

## Performance acceptance benchmark

The provisional local acceptance workload is 20 simultaneous clients against
one application instance, with bcrypt cost 12, authentication rate limits,
JWT validation and a temporary file-backed SQLite database enabled:

- 20 concurrent valid login requests for 20 distinct accounts: 100% HTTP 200,
  p95 at most 2,000 ms.
- 100 authenticated profile requests from 20 concurrent clients: 100% HTTP 200,
  p95 at most 500 ms.

Run from this directory using
`mvn "-Dtest=UserPerformanceBenchmark" test`. The benchmark starts an embedded
HTTP server and temporary database, seeds 20 verified users, warms up requests,
reports p50/p95/maximum latency and throughput, and fails if a target is missed.
Percentiles use the nearest-rank method. Login uses 20 simultaneous requests
from one loopback IP; together with three warm-up requests
this remains below the 30-request IP rate limit. The benchmark uses fake email
delivery; a sustained login rate from one IP would hit that limit. It does not
measure live SMTP, external TLS/proxies, mixed traffic or
long-duration stability, and its short sample is not a production capacity test.
Run on representative deployment hardware and agree on production workload
and targets before making a production performance claim.

On the local test machine (2 physical cores, 4 logical processors, Java 21),
the distinct-account baseline login p95 was 5,724 ms. After moving password
verification outside the SQLite transaction while reserving attempts in the
shared database, two runs measured login p95 1,815 ms and 1,832 ms and profile
p95 112 ms and 94 ms, respectively, with no request errors. Both runs met the
local criteria, but the margin is small and the workload is too short to
establish production capacity. Do not reduce the bcrypt work factor or
disable security controls to pass this benchmark.

## Existing databases

Back up the SQLite database and verify your SMTP configuration before upgrading.
Stop all old application instances before deploying this version: older
instances do not account for in-flight reservations and must not share the
database with the new version during a rolling upgrade.
At startup, the transactional
migration canonicalizes email addresses, requires them to be unique, marks
pre-existing accounts as unverified, and replaces legacy MD5 hashes with a
disabled marker. If email addresses collide, startup fails and the transaction
is rolled back: an administrator must review and resolve the duplicates without
automatically merging accounts. Existing accounts must use email recovery to
set a new password. Previously issued access tokens are invalid.
Tokens issued before issuer and audience validation were introduced are also
invalid; users must authenticate again.

Old database backups may still contain MD5 hashes; protect or retire them
according to your retention policy. The migration does not remove old backups.
The `UserManager` constructor and registration/reset APIs have changed to
require an email sender and email verification.
