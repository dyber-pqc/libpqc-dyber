/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * KEM (Key Encapsulation Mechanism) class.
 */

'use strict';

const addon = require('../build/Release/pqc_addon.node');

class KEM {
    /**
     * Create a KEM instance for the given algorithm.
     * @param {string} algorithm - e.g. "ML-KEM-768"
     */
    constructor(algorithm) {
        if (typeof algorithm !== 'string' || algorithm.length === 0) {
            throw new TypeError('algorithm must be a non-empty string');
        }
        this._algorithm = algorithm;
    }

    /** @returns {string} The algorithm name. */
    get algorithm() {
        return this._algorithm;
    }

    /**
     * Generate a keypair.
     * @returns {{ publicKey: Buffer, secretKey: Buffer }}
     */
    keygen() {
        return addon.kemKeygen(this._algorithm);
    }

    /**
     * Encapsulate a shared secret with a public key.
     * @param {Buffer} publicKey
     * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }}
     */
    encaps(publicKey) {
        if (!Buffer.isBuffer(publicKey)) {
            throw new TypeError('publicKey must be a Buffer');
        }
        return addon.kemEncaps(this._algorithm, publicKey);
    }

    /**
     * Decapsulate a shared secret from a ciphertext using a secret key.
     * @param {Buffer} ciphertext
     * @param {Buffer} secretKey
     * @returns {Buffer} The shared secret.
     */
    decaps(ciphertext, secretKey) {
        if (!Buffer.isBuffer(ciphertext)) {
            throw new TypeError('ciphertext must be a Buffer');
        }
        if (!Buffer.isBuffer(secretKey)) {
            throw new TypeError('secretKey must be a Buffer');
        }
        return addon.kemDecaps(this._algorithm, ciphertext, secretKey);
    }
}

module.exports = { KEM };
