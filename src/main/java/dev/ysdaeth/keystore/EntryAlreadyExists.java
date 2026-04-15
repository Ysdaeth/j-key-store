package dev.ysdaeth.keystore;

public class EntryAlreadyExists extends RuntimeException {
    public EntryAlreadyExists(String message) {
        super(message);
    }
}
