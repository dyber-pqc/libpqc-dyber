/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

package com.dyber.pqc;

/**
 * Exception thrown by libpqc operations on failure.
 */
public class PQCException extends Exception {

    /** Status code constants matching pqc_status_t. */
    public static final int OK = 0;
    public static final int ERROR = -1;
    public static final int INVALID_ARGUMENT = -2;
    public static final int ALLOC = -3;
    public static final int NOT_SUPPORTED = -4;
    public static final int INVALID_KEY = -5;
    public static final int VERIFICATION_FAILED = -6;
    public static final int DECAPSULATION_FAILED = -7;
    public static final int RNG_FAILED = -8;
    public static final int BUFFER_TOO_SMALL = -9;
    public static final int INTERNAL = -10;
    public static final int STATE_EXHAUSTED = -11;

    private final int statusCode;

    /**
     * Create a new PQCException with the given status code and message.
     *
     * @param statusCode the pqc_status_t value
     * @param message    human-readable error description
     */
    public PQCException(int statusCode, String message) {
        super(message + " (status " + statusCode + ")");
        this.statusCode = statusCode;
    }

    /**
     * Create a new PQCException from a status code, looking up the message
     * from the C library.
     *
     * @param statusCode the pqc_status_t value
     */
    public PQCException(int statusCode) {
        this(statusCode, PQC.statusString(statusCode));
    }

    /**
     * Return the raw pqc_status_t code.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Check a status code and throw if not OK.
     *
     * @param status the status to check
     * @throws PQCException if status is not PQC_OK
     */
    static void checkStatus(int status) throws PQCException {
        if (status != OK) {
            throw new PQCException(status);
        }
    }
}
