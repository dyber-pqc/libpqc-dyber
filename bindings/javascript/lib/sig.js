/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Signature class.
 */

'use strict';

const addon = require('../build/Release/pqc_addon.node');

class Signature {
    /**
     * Create a Signature instance for the given algorithm.
     * @param {string} algorithm - e.g. "ML-DSA-65"
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
        return addon.sigKeygen(this._algorithm);
    }

    /**
     * Sign a message.
     * @param {Buffer} message
     * @param {Buffer} secretKey
     * @returns {Buffer} The signature.
     */
    sign(message, secretKey) {
        if (!Buffer.isBuffer(message)) {
            throw new TypeError('message must be a Buffer');
        }
        if (!Buffer.isBuffer(secretKey)) {
            throw new TypeError('secretKey must be a Buffer');
        }
        return addon.sigSign(this._algorithm, message, secretKey);
    }

    /**
     * Verify a signature.
     * @param {Buffer} message
     * @param {Buffer} signature
     * @param {Buffer} publicKey
     * @returns {boolean} True if valid.
     */
    verify(message, signature, publicKey) {
        if (!Buffer.isBuffer(message)) {
            throw new TypeError('message must be a Buffer');
        }
        if (!Buffer.isBuffer(signature)) {
            throw new TypeError('signature must be a Buffer');
        }
        if (!Buffer.isBuffer(publicKey)) {
            throw new TypeError('publicKey must be a Buffer');
        }
        return addon.sigVerify(this._algorithm, message, signature, publicKey);
    }
}

module.exports = { Signature };
