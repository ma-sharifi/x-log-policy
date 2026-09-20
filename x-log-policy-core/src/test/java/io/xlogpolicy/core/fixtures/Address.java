package io.xlogpolicy.core.fixtures;

import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.PolicyType;

/** A nested bean: reached only when the property referencing it is descended into. */
public class Address {

    @LogPolicy(PolicyType.MASK)
    public String street;

    @LogPolicy(PolicyType.SAFE)
    public String city;

    @LogPolicy(PolicyType.SAFE)
    public String country;

    /** No policy: masked by the default. */
    public String postalCode;

    public static Address sample() {
        Address address = new Address();
        address.street = "Hollandstraat 1";
        address.city = "Amsterdam";
        address.country = "NL";
        address.postalCode = "1012 AB";
        return address;
    }
}
