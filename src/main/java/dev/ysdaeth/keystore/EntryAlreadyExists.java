package dev.ysdaeth.keystore;

/**
 * Exception is thrown when entry with specified alias already exists.
 */
public class EntryAlreadyExists extends RuntimeException {
    public EntryAlreadyExists(String message) {
        super(message);
    }
}
