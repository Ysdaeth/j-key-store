package dev.ysdaeth.keystore;

/**
 * When provided key to recover does not match return type.
 */
public class KeyEntrySymmetryException extends KeyEntryException {

    public KeyEntrySymmetryException(String message) {
        super(message);
    }
}
