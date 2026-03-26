/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Main entry point for @dyber/pqc Node.js bindings.
 */

'use strict';

const { KEM } = require('./kem');
const { Signature } = require('./sig');

const addon = require('../build/Release/pqc_addon.node');

/**
 * Get the library version string.
 * @returns {string}
 */
function version() {
    return addon.version();
}

/**
 * List all available KEM algorithm names.
 * @returns {string[]}
 */
function kemAlgorithms() {
    return addon.kemAlgorithms();
}

/**
 * List all available signature algorithm names.
 * @returns {string[]}
 */
function sigAlgorithms() {
    return addon.sigAlgorithms();
}

module.exports = {
    version,
    kemAlgorithms,
    sigAlgorithms,
    KEM,
    Signature,
};
