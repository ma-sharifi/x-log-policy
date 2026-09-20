package io.xlogpolicy.demo;

import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.demo.model.Customer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Business logic that logs its inputs. The only rule a developer has to remember: pass objects through
 * {@link LogRedactor#toSafeJson(Object)} instead of relying on {@code toString()}.
 */
@Service
public class CustomerService {

    private static final Logger log = LoggerFactory.getLogger(CustomerService.class);

    private final Map<String, Customer> customers = new ConcurrentHashMap<>();
    private final LogRedactor redactor;

    public CustomerService(LogRedactor redactor) {
        this.redactor = redactor;
    }

    public Customer store(Customer customer) {
        // The one line that matters: everything the spec declared is applied here.
        log.info("storing customer {}", redactor.toSafeJson(customer));
        customers.put(customer.getId(), customer);
        return customer;
    }

    public Optional<Customer> find(String id) {
        Optional<Customer> found = Optional.ofNullable(customers.get(id));
        log.info("lookup of customer {} {}", redactor.redactValue(Customer.class, "id", id),
                found.isPresent() ? "hit" : "miss");
        return found;
    }
}
