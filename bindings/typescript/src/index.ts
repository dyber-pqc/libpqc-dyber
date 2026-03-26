/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * TypeScript type definitions for @dyber/pqc.
 */

/** KEM keypair result. */
export interface KEMKeyPair {
    publicKey: Buffer;
    secretKey: Buffer;
}

/** KEM encapsulation result. */
export interface KEMEncapsResult {
    ciphertext: Buffer;
    sharedSecret: Buffer;
}

/** Signature keypair result. */
export interface SignatureKeyPair {
    publicKey: Buffer;
    secretKey: Buffer;
}

/**
 * Key Encapsulation Mechanism (KEM) class.
 */
export declare class KEM {
    constructor(algorithm: string);

    /** The algorithm name. */
    readonly algorithm: string;

    /** Generate a new keypair. */
    keygen(): KEMKeyPair;

    /** Encapsulate: generate shared secret and ciphertext from a public key. */
    encaps(publicKey: Buffer): KEMEncapsResult;

    /** Decapsulate: recover shared secret from ciphertext using secret key. */
    decaps(ciphertext: Buffer, secretKey: Buffer): Buffer;
}

/**
 * Digital Signature class.
 */
export declare class Signature {
    constructor(algorithm: string);

    /** The algorithm name. */
    readonly algorithm: string;

    /** Generate a new keypair. */
    keygen(): SignatureKeyPair;

    /** Sign a message with a secret key. */
    sign(message: Buffer, secretKey: Buffer): Buffer;

    /** Verify a signature against a message and public key. */
    verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean;
}

/** Get the library version string. */
export declare function version(): string;

/** List all available KEM algorithm names. */
export declare function kemAlgorithms(): string[];

/** List all available signature algorithm names. */
export declare function sigAlgorithms(): string[];

/** Well-known KEM algorithm name constants. */
export declare const KEM_ALGORITHMS: {
    readonly ML_KEM_512: 'ML-KEM-512';
    readonly ML_KEM_768: 'ML-KEM-768';
    readonly ML_KEM_1024: 'ML-KEM-1024';
    readonly HQC_128: 'HQC-128';
    readonly HQC_192: 'HQC-192';
    readonly HQC_256: 'HQC-256';
    readonly BIKE_L1: 'BIKE-L1';
    readonly BIKE_L3: 'BIKE-L3';
    readonly BIKE_L5: 'BIKE-L5';
};

/** Well-known signature algorithm name constants. */
export declare const SIG_ALGORITHMS: {
    readonly ML_DSA_44: 'ML-DSA-44';
    readonly ML_DSA_65: 'ML-DSA-65';
    readonly ML_DSA_87: 'ML-DSA-87';
    readonly FN_DSA_512: 'FN-DSA-512';
    readonly FN_DSA_1024: 'FN-DSA-1024';
    readonly SLH_DSA_SHA2_128S: 'SLH-DSA-SHA2-128s';
    readonly SLH_DSA_SHA2_128F: 'SLH-DSA-SHA2-128f';
};
