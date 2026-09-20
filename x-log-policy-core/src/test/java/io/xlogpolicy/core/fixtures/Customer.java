package io.xlogpolicy.core.fixtures;

import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.PolicyType;

import java.util.List;
import java.util.Map;

/** Covers every policy plus the interesting shapes: nested bean, collections, free-form map. */
public class Customer {

    @LogPolicy(PolicyType.SAFE)
    public String id;

    @LogPolicy(PolicyType.MASK)
    public String ssn;

    @LogPolicy(value = PolicyType.PARTIAL, keep = 4)
    public String cardNumber;

    @LogPolicy(PolicyType.HMAC)
    public String email;

    @LogPolicy(PolicyType.HASH)
    public String phone;

    @LogPolicy(PolicyType.DROP)
    public String internalNote;

    @LogPolicy(value = PolicyType.CUSTOM, name = "initials")
    public String fullName;

    @LogPolicy(PolicyType.SAFE)
    public int age;

    @LogPolicy(PolicyType.MASK)
    public Integer creditScore;

    /** No policy, value-like: must be masked by the fail-closed default. */
    public String nickname;

    /** No policy, structured: must be descended into. */
    public Address address;

    @LogPolicy(PolicyType.SAFE)
    public List<String> tags;

    /** No policy, collection of values: every element must be masked. */
    public List<String> priorAddresses;

    @LogPolicy(PolicyType.MASK)
    public List<String> accountNumbers;

    /** No policy, free-form: each key is resolved by name. */
    public Map<String, Object> attributes;

    /** No policy, collection of beans: elements must be descended into. */
    public List<Address> previousAddresses;

    public static Customer sample() {
        Customer customer = new Customer();
        customer.id = "c-17";
        customer.ssn = "123-45-6789";
        customer.cardNumber = "4111111111111234";
        customer.email = "ada@example.com";
        customer.phone = "+31 6 1234 5678";
        customer.internalNote = "called twice about the chargeback";
        customer.fullName = "Ada Lovelace";
        customer.age = 36;
        customer.creditScore = 720;
        customer.nickname = "Ada";
        customer.address = Address.sample();
        customer.tags = List.of("premium", "eu");
        customer.priorAddresses = List.of("Hollandstraat 1", "Kerkstraat 9");
        customer.accountNumbers = List.of("NL91ABNA0417164300", "NL02RABO0123456789");
        customer.attributes = new java.util.LinkedHashMap<>(Map.of("segment", "gold"));
        customer.attributes.put("ssn", "987-65-4321");
        customer.previousAddresses = List.of(Address.sample());
        return customer;
    }
}
