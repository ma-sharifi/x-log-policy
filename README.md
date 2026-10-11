# x-log-policy

Declare in the OpenAPI document — or the Avro schema — how each field may appear in logs, and have every
implementation of that API, and every consumer of that event, obey it.

```yaml
Customer:
  type: object
  properties:
    id:         { type: string, x-log-policy: SAFE }
    email:      { type: string, x-log-policy: HMAC }
    ssn:        { type: string, x-log-policy: MASK }
    cardNumber: { type: string, x-log-policy: { policy: PARTIAL, keep: 4 } }
```

```java
log.info("storing customer {}", redactor.toSafeJson(customer));
```

```
storing customer {"id":"c-42","email":"hmac:a3e6a794","ssn":"***","cardNumber":"************1234", …}
```

The API still returns the real data. Only the log is redacted.

## Why

Redaction is normally decided per service, by hand, and drifts from the contract. Putting the policy next
to the schema makes it reviewable in the same pull request as the field itself, and makes the same
decision apply to every service, client and generated model built from that document.

The starter is **fail-closed**: a field nothing declares is masked. A field has to be marked `SAFE` to be
readable. That is what keeps a new personal-data field from leaking by being forgotten.

## Modules

| Module | What it is |
| --- | --- |
| `x-log-policy-core` | `@LogPolicy`, the policy model and the Jackson-based `LogRedactor`. Plain Java, no Spring. |
| `x-log-policy-avro` | `AvroLogRedactor`: renders Avro records from the `x-log-policy` in their own schema. Plain Java, no Spring. |
| `x-log-policy-spring-boot-starter` | Auto-configures the redactor, optional HTTP payload logging, and Logback/Log4j2 converters. |
| `x-log-policy-maven-plugin` | Reads the spec (OpenAPI or `.avsc`): stamps `@LogPolicy` onto generated models, gives generated Avro records a redacted `toString()`, writes the runtime registry, and fails the build on uncovered fields. |
| `x-log-policy-demo` | A service proving all of it end to end. Not published. |

## Getting started

### 1. Declare policies in the spec

See [docs/x-log-policy.md](docs/x-log-policy.md) for the full extension reference and the policy table.

### 2. Add the plugin

```xml
<plugin>
  <groupId>io.xlogpolicy</groupId>
  <artifactId>x-log-policy-maven-plugin</artifactId>
  <version>0.1.0-SNAPSHOT</version>
  <executions>
    <execution>
      <goals>
        <goal>annotate-sources</goal>   <!-- @LogPolicy onto generated models -->
        <goal>generate-metadata</goal>  <!-- META-INF/x-log-policy.json for everything else -->
        <goal>validate</goal>           <!-- fail the build on uncovered PII-looking fields -->
      </goals>
      <configuration>
        <specs>
          <spec>src/main/resources/openapi/customer-api.yaml</spec>
        </specs>
      </configuration>
    </execution>
  </executions>
</plugin>
```

### 3. Add the starter

```xml
<dependency>
  <groupId>io.xlogpolicy</groupId>
  <artifactId>x-log-policy-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

### 4. Log through the redactor

```java
@Service
class CustomerService {
    private static final Logger log = LoggerFactory.getLogger(CustomerService.class);
    private final LogRedactor redactor;

    CustomerService(LogRedactor redactor) {
        this.redactor = redactor;
    }

    void store(Customer customer) {
        log.info("storing customer {}", redactor.toSafeJson(customer));
    }
}
```

`LogRedactor` never throws and never blocks: a failure to render becomes
`{"_redactionError":"…"}` in the log rather than an exception in your request.

## Avro

The same extension works in an Avro schema. Avro keeps attributes it does not know as schema properties,
so the schema designer declares the policy next to the field and it travels with the schema: into the
`SCHEMA$` of every generated class, and into the writer schema every consumer decodes with.

```json
{"type": "record", "name": "CustomerRegistered", "fields": [
  {"name": "customerId",   "type": "string", "x-log-policy": "SAFE"},
  {"name": "email",        "type": "string", "x-log-policy": "HMAC"},
  {"name": "ssn",          "type": ["null", "string"], "default": null, "x-log-policy": "MASK"},
  {"name": "cardNumber",   "type": "string", "x-log-policy": {"policy": "PARTIAL", "keep": 4}},
  {"name": "phoneNumbers", "type": {"type": "array", "items": "string", "x-log-policy": "HASH"}},
  {"name": "internalNote", "type": ["null", "string"], "default": null, "x-log-policy": "DROP"},
  {"name": "address",      "type": "PostalAddress"}
]}
```

On the consumer side, add `x-log-policy-avro` and have the build rewrite the classes `avro-maven-plugin`
generates:

```xml
<dependency>
  <groupId>io.xlogpolicy</groupId>
  <artifactId>x-log-policy-avro</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```xml
<plugin>
  <groupId>io.xlogpolicy</groupId>
  <artifactId>x-log-policy-maven-plugin</artifactId>
  <version>0.1.0-SNAPSHOT</version>
  <executions>
    <execution>
      <goals>
        <goal>avro-safe-tostring</goal>  <!-- generated records get a redacted toString() -->
        <goal>validate</goal>            <!-- fail the build on uncovered PII-looking fields -->
      </goals>
      <configuration>
        <specs>
          <spec>src/main/avro/customer-registered.avsc</spec>
        </specs>
      </configuration>
    </execution>
  </executions>
</plugin>
```

Declare it after `avro-maven-plugin`, so it runs on the freshly generated sources. Then:

```java
log.info("received {}", event);                     // toString() is redacted
log.info("received {}", redactor.toSafeJson(event)); // the same, through the injected LogRedactor
```

```
received {"customerId":"c-42","email":"hmac:a3e6a794","ssn":"***","cardNumber":"************1234",
          "phoneNumbers":["sha256:fab7be8a"],"address":{"street":"***","postalCode":"****AB",…}}
```

The redacted `toString()` matters more for events than for REST payloads: Kafka clients, error handlers
and dead-letter publishers log the record they failed on, and that is code you do not get to change.
`SpecificData.get().toString(event)` still gives the unredacted form where it is genuinely needed.

- **The schema is the registry.** Policies are read at runtime from the record's own schema, so nothing
  has to be generated for them, and a `GenericRecord` consumer without generated classes is covered too —
  call `redactor.toSafeJson(record)`.
- **With the starter**, the `LogRedactor` bean becomes Avro-aware as soon as `x-log-policy-avro` is on the
  classpath: Avro records are rendered from their schema, everything else as before, and `overrides`,
  `default-policy`, the HMAC secret and the limits apply to both. Overrides name the record:
  `"[CustomerRegistered.ssn]": DROP`.
- **Without Spring**, call `AvroLogRedactor.install(…)` once at startup with your settings; otherwise
  generated records use defaults, including a random per-JVM HMAC key.
- **`validate` and `generate-metadata`** accept `.avsc` files in `<specs>` alongside OpenAPI documents.
  Schemas are parsed together in the order listed, so a later file may use a type an earlier one defines.

See [docs/x-log-policy.md](docs/x-log-policy.md#avro) for where the policy may appear in an Avro schema.

## Configuration

```yaml
x-log-policy:
  default-policy: MASK              # policy for anything undeclared; SAFE makes it fail-open
  mask-token: "***"
  partial-keep: 4                   # trailing characters kept by PARTIAL
  digest-length: 8                  # hex characters kept from HASH / HMAC
  load-metadata: true               # read META-INF/x-log-policy.json
  max-string-length: 2048           # truncate long SAFE text
  max-json-length: 16384            # truncate the rendered JSON
  max-depth: 24                     # deeper graphs (and cycles) yield a placeholder
  max-collection-size: 100
  pretty-print: false
  hmac:
    secret: ${LOG_HMAC_SECRET}      # required for HMAC/TOKENIZE to correlate across restarts
  overrides:                        # highest precedence; no rebuild needed
    "[Customer.ssn]": DROP
    "[*.email]": HMAC
  http:
    enabled: false                  # opt in to request/response logging
    include-request-body: true
    include-response-body: false
    max-payload-length: 2048
    include-headers: [X-Caller-Email]
    exclude-paths: ["/actuator/**"]
```

**Precedence**, highest first: configuration override → `@LogPolicy` on the property → `@LogPolicy` on the
type → the spec registry for that schema → the spec registry by property name → `default-policy`.
Configuration beats annotations on purpose: an operator needs a way to tighten (or, locally, relax) a
policy without a release.

## Extension points

Every bean is `@ConditionalOnMissingBean`, so anything can be replaced:

```java
@Bean ValueRedaction initials() { … }      // named "initials" -> x-log-policy: {policy: CUSTOM, name: initials}
@Bean ValueRedaction mask() { … }          // named "MASK" -> replaces the built-in
@Bean Tokenizer tokenizer() { … }          // backs the TOKENIZE policy
@Bean LogRedactor logRedactor(…) { … }     // replaces the whole thing
```

## Defence in depth

1. **`LogRedactor.toSafeJson`** — the mechanism. Exhaustive: every property of every nested object,
   collection element and map value is resolved, and anything undeclared is masked.
2. **HTTP payload logging** (`x-log-policy.http.enabled=true`) — request and response bodies redacted key
   by key against the registry, so an undocumented field in a payload cannot leak either.
3. **`%safeMsg`** — a Logback/Log4j2 pattern converter that redacts declared fields inside any already
   formatted message, for code that logs an object directly. A net, not the mechanism: it only sees
   JSON-shaped text and only applies explicitly declared policies.

```xml
<conversionRule conversionWord="safeMsg" class="io.xlogpolicy.spring.logback.SafeMessageConverter"/>
<pattern>%d{HH:mm:ss.SSS} %-5level %logger{28} - %safeMsg%n</pattern>
```

## Building

Requires JDK 17+ and Maven 3.6.3+ (built and tested on JDK 25 / Maven 3.9).

```bash
mvn clean install     # 150 tests across the five modules
```

`install` rather than `verify`: the demo module uses the Maven plugin built in the same reactor, and Maven
resolves plugins from the local repository.

Run the demo:

```bash
mvn -pl x-log-policy-demo spring-boot:run

curl -s -X POST localhost:8080/customers -H 'Content-Type: application/json' \
  -H 'X-Caller-Email: operator@example.com' \
  -d '{"id":"c-42","email":"ada@example.com","ssn":"123-45-6789",
       "cardNumber":"4111111111111234","fullName":"Ada Lovelace",
       "internalNote":"chargeback dispute",
       "address":{"street":"Hollandstraat","postalCode":"1012AB","city":"Amsterdam","country":"NL"}}'
```

The response carries the real data; the console shows `"ssn":"***"`, `"cardNumber":"************1234"`,
`"email":"hmac:…"`, `"postalCode":"****AB"`, `"city":"Amsterdam"`, and no `internalNote` at all.

## Known limits

- **`%safeMsg` is best-effort.** It recognises JSON-shaped `"field": value` pairs only, and applies only
  explicitly declared policies — applying the fail-closed default to arbitrary text would blank out every
  unrelated log message. It skips values that already look redacted, so built-in policies are idempotent;
  a custom redaction used with `%safeMsg` should be idempotent too.
- **Body logging needs the registry.** A bare JSON key has no annotation to read, so HTTP payload
  redaction resolves names through `META-INF/x-log-policy.json`.
- **Avro inside a POJO.** `AvroLogRedactor` handles an Avro record passed to it directly; one nested
  inside an ordinary Java object is rendered by the Jackson redactor, which does not know Avro. Log the
  record itself.
- **A hand-written `toString()` wins.** `avro-safe-tostring` leaves a record class that already declares
  one alone, and warns.
- **Schema matching is by name.** A model class is matched to a schema by simple name, with a common
  generator suffix stripped (`CustomerDto` → `Customer`).
- **The PII heuristic is a heuristic.** `validate` flags leaf properties whose names look like personal
  data; tune it with `<additionalPatterns>` and `<excludes>`.
