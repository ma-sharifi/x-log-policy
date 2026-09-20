# The `x-log-policy` extension

A specification-level reference for the extension, independent of the Java implementation. Any language
can implement it; this document is what an implementation has to agree with.

## Synopsis

`x-log-policy` declares how a value may appear in logs. It is an OpenAPI 3 specification extension and is
ignored by tooling that does not know it.

```yaml
components:
  schemas:
    Customer:
      type: object
      properties:
        id:         { type: string, x-log-policy: SAFE }
        ssn:        { type: string, x-log-policy: MASK }
        cardNumber: { type: string, x-log-policy: { policy: PARTIAL, keep: 4 } }
```

## Forms

**Scalar** — the policy name on its own:

```yaml
x-log-policy: MASK
```

**Object** — a policy with parameters:

```yaml
x-log-policy:
  policy: PARTIAL      # also accepted: value, type
  keep: 4              # also accepted: keepLast, visible
  name: myRedaction    # required for CUSTOM; also accepted: redaction
  params: { … }        # passed through to a custom redaction
```

Policy names are case-insensitive and `-`/`_` are interchangeable. These aliases are accepted:
`NONE`/`PLAIN` → `SAFE`, `REDACT` → `MASK`, `PARTIAL_MASK` → `PARTIAL`, `SHA256` → `HASH`,
`HMAC_SHA256` → `HMAC`, `TOKEN` → `TOKENIZE`, `OMIT`/`REMOVE` → `DROP`.

## Policies

| Policy | `4111111111111234` becomes | Notes |
| --- | --- | --- |
| `SAFE` | `4111111111111234` | Declared non-sensitive. The only policy that makes a value readable. |
| `MASK` | `***` | Nothing survives, not even the length. |
| `PARTIAL` | `************1234` | `keep` trailing characters survive (default 4). Shorter values are fully masked. |
| `HASH` | `sha256:9f86d081` | Unkeyed. Correlatable — but so is a dictionary attack on a low-entropy value. |
| `HMAC` | `hmac:7d3a9c12` | Keyed. The right choice for correlating a person across log lines. |
| `TOKENIZE` | whatever the tokenizer returns | For a real tokenization service. |
| `DROP` | *property absent* | Removed from output entirely, not even the key. |
| `CUSTOM` | whatever the named redaction returns | Dispatched by `name`. |

## Where it may appear

| Position | Meaning |
| --- | --- |
| `properties.<name>` | The policy for that property. The common case. |
| the schema itself | Default for every property of that schema; a property's own policy wins. |
| `items` | Policy for the elements, which is the same as policing the array property. |
| `additionalProperties` | Policy for the values of a free-form map. |
| `parameters[].` or its `schema` | Policy for a query, path or header parameter. |
| `headers.<name>` | Policy for a response header. |

A property that points at another schema — a `$ref`, an inline object, a composition, or an array or map
of those — needs **no** policy. Such a property is descended into, so the nested fields apply their own
policies. Declaring a policy there would collapse the whole object into one redacted token, which is
occasionally what you want, and is why it remains allowed.

```yaml
Customer:
  properties:
    address:                            # no policy: descended into
      $ref: '#/components/schemas/Address'
    priorAddresses:                     # policy on items: every element redacted
      type: array
      items: { type: string, x-log-policy: MASK }
    attributes:                         # policy on values of a free-form map
      type: object
      additionalProperties: { type: string, x-log-policy: MASK }
Address:
  properties:
    street:     { type: string, x-log-policy: MASK }
    postalCode: { type: string, x-log-policy: { policy: PARTIAL, keep: 2 } }
    city:       { type: string, x-log-policy: SAFE }
```

## Choosing a policy

- **Is it needed in a log at all?** If not, `DROP`. Free-text notes and internal comments belong here:
  they are the fields most likely to contain something nobody expected.
- **Does support need to recognise the value?** `PARTIAL`, with the smallest `keep` that works.
- **Does anything need to correlate it across lines or services?** `HMAC`, with a secret shared by the
  services that must agree. Never `HASH` for a low-entropy value such as a phone number or a postcode —
  an unkeyed digest of a value from a small domain is reversible by brute force.
- **Is it genuinely not personal data?** `SAFE` — and say so explicitly, because the default is to hide.
- **Everything else:** `MASK`.

Identifiers deserve a moment's thought. An opaque surrogate key is usually `SAFE`; a natural key such as
an email address, a phone number or a national identifier is not, even when it is also the primary key.

## Implementation requirements

An implementation of this extension is expected to:

1. **Fail closed by default.** A value that no policy covers is redacted, not logged. This is the property
   that makes the extension worth having: it turns "someone remembered" into "someone would have to
   override it".
2. **Recurse.** Nested objects, collection elements and map values are resolved individually. A policy on
   a container applies to everything inside it.
3. **Never throw.** A failure to redact is reported inside the output, never raised to the caller. Logging
   must not be able to fail a request.
4. **Bound its output.** Depth, string length, collection size and total length are all capped, so a
   cyclic or enormous object graph cannot take a process down through its log statements.
5. **Leave the API alone.** Redaction applies to logs only. Responses carry the real data; an
   implementation must not reuse the serializer that produces HTTP responses.
6. **Report what it does not cover.** A field whose name suggests personal data but declares no policy is
   a finding, ideally one that fails a build.

## Reference implementation

`io.xlogpolicy:x-log-policy-spring-boot-starter` — see the [README](../README.md). Policies reach the
runtime two ways: `@LogPolicy` annotations stamped onto generated models at build time, and a generated
registry (`META-INF/x-log-policy.json`) that also covers hand-written types, third-party types and
free-form JSON.

### The generated registry

```json
{
  "version": 1,
  "schemas":     { "Customer": { "ssn": { "policy": "MASK" } } },
  "byFieldName": { "ssn": { "policy": "MASK" } }
}
```

`schemas` is the precise index, used when a type can be matched to a schema. `byFieldName` is the fallback
for map keys, headers and free-form JSON, where only a name is available; when the same name carries
different policies in different schemas, **the strictest one wins**
(`DROP` > `MASK` > `CUSTOM` > `HMAC` > `TOKENIZE` > `HASH` > `PARTIAL` > `SAFE`).
