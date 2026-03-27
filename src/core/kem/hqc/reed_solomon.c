/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC - Reed-Solomon codec over GF(2^m).
 *
 * Implements RS encoding (systematic), syndrome computation,
 * Berlekamp-Massey error locator, Chien search, Forney error
 * evaluation, and full decode.
 */

#include <string.h>
#include <stdlib.h>
#include "hqc.h"
#include "hqc_params.h"

/* Maximum RS redundancy symbols (2 * delta). delta_max = 29 => g_max = 58. */
#define RS_MAX_G  64
#define RS_MAX_N1 96

/* ------------------------------------------------------------------ */
/* Generator polynomial computation                                     */
/*                                                                      */
/* g(x) = prod_{i=1}^{2*delta} (x - alpha^i)                          */
/* ------------------------------------------------------------------ */

static void rs_compute_generator(hqc_gf_t *g, uint32_t g_deg, uint32_t m)
{
    memset(g, 0, (g_deg + 1) * sizeof(hqc_gf_t));
    g[0] = 1;

    for (uint32_t i = 1; i <= g_deg; i++) {
        hqc_gf_t alpha_i = hqc_gf_exp(i, m);
        /* Multiply g by (x - alpha^i) = (x + alpha^i) in GF(2^m) */
        for (int j = (int)i; j >= 1; j--) {
            g[j] = g[j - 1] ^ hqc_gf_mul(g[j], alpha_i, m);
        }
        g[0] = hqc_gf_mul(g[0], alpha_i, m);
    }
}

/* ------------------------------------------------------------------ */
/* RS Encoding (systematic)                                             */
/*                                                                      */
/* message has k symbols, codeword has n1 symbols.                      */
/* codeword = [message | parity], where parity = msg(x) * x^g mod g(x) */
/* ------------------------------------------------------------------ */

void hqc_rs_encode(uint8_t *codeword, const uint8_t *message,
                   const hqc_params_t *params)
{
    uint32_t n1 = params->n1;
    uint32_t k  = params->k;
    uint32_t g_deg = params->g;
    uint32_t m  = params->m;

    hqc_gf_t gen[RS_MAX_G + 1];
    hqc_gf_t parity[RS_MAX_G];

    /* Initialize GF tables */
    hqc_gf_generate_tables(m);

    /* Compute generator polynomial */
    rs_compute_generator(gen, g_deg, m);

    /*
     * Systematic RS encoding with the polynomial convention that
     * codeword[j] is the coefficient of x^j.
     *
     * We place the message at the high-degree positions:
     *   c(x) = m(x) * x^g - r(x)
     * where m(x) = message[0]*x^0 + ... + message[k-1]*x^{k-1}
     * and r(x) = (m(x) * x^g) mod g(x).
     *
     * The codeword layout is: [parity (g bytes) | message (k bytes)]
     *   codeword[0..g-1]   = parity (low degree)
     *   codeword[g..n1-1]  = message (high degree)
     *
     * This ensures c(alpha^i) = 0 for i = 1..2*delta.
     */

    /* Compute parity = m(x)*x^g mod g(x) using polynomial long division.
     * We process message coefficients from highest degree down:
     * m[k-1]*x^{k-1+g}, m[k-2]*x^{k-2+g}, ..., m[0]*x^{g}
     */
    memset(parity, 0, sizeof(parity));
    for (int i = (int)k - 1; i >= 0; i--) {
        hqc_gf_t feedback = (hqc_gf_t)message[i] ^ parity[g_deg - 1];
        for (int j = (int)g_deg - 1; j > 0; j--) {
            parity[j] = parity[j - 1] ^ hqc_gf_mul(gen[j], feedback, m);
        }
        parity[0] = hqc_gf_mul(gen[0], feedback, m);
    }

    /* Assemble codeword: [parity | message] */
    memset(codeword, 0, n1);
    for (uint32_t i = 0; i < g_deg; i++) {
        codeword[i] = (uint8_t)parity[i];
    }
    for (uint32_t i = 0; i < k; i++) {
        codeword[g_deg + i] = message[i];
    }
}

/* ------------------------------------------------------------------ */
/* Syndrome computation                                                 */
/*                                                                      */
/* S_i = r(alpha^i) for i = 1..2*delta                                 */
/* ------------------------------------------------------------------ */

static void rs_compute_syndromes(hqc_gf_t *syndromes, const uint8_t *received,
                                 uint32_t n1, uint32_t g_deg, uint32_t m)
{
    for (uint32_t i = 1; i <= g_deg; i++) {
        hqc_gf_t s = 0;
        hqc_gf_t alpha_pow = 1;
        hqc_gf_t alpha_i = hqc_gf_exp(i, m);
        for (uint32_t j = 0; j < n1; j++) {
            if (received[j]) {
                s ^= hqc_gf_mul((hqc_gf_t)received[j], alpha_pow, m);
            }
            alpha_pow = hqc_gf_mul(alpha_pow, alpha_i, m);
        }
        syndromes[i - 1] = s;
    }
}

/* ------------------------------------------------------------------ */
/* Berlekamp-Massey algorithm                                           */
/*                                                                      */
/* Finds the error locator polynomial sigma(x) from syndromes.         */
/* Returns the degree of sigma (= number of errors).                    */
/* ------------------------------------------------------------------ */

static uint32_t rs_berlekamp_massey(hqc_gf_t *sigma, const hqc_gf_t *syndromes,
                                    uint32_t g_deg, uint32_t m)
{
    hqc_gf_t C[RS_MAX_G + 1]; /* current LFSR connection polynomial */
    hqc_gf_t B[RS_MAX_G + 1]; /* previous polynomial */
    hqc_gf_t T[RS_MAX_G + 1]; /* temp */

    memset(C, 0, sizeof(C));
    memset(B, 0, sizeof(B));
    C[0] = 1;
    B[0] = 1;

    uint32_t L = 0;  /* current LFSR length */
    int b = 1;       /* discrepancy step counter */

    for (uint32_t n = 0; n < g_deg; n++) {
        /* Compute discrepancy */
        hqc_gf_t d = syndromes[n];
        for (uint32_t i = 1; i <= L; i++) {
            d ^= hqc_gf_mul(C[i], syndromes[n - i], m);
        }

        if (d == 0) {
            b++;
        } else {
            memcpy(T, C, sizeof(T));

            /* C(x) = C(x) - d * x^b * B(x) */
            for (uint32_t i = 0; i + (uint32_t)b <= g_deg; i++) {
                if (B[i]) {
                    C[i + b] ^= hqc_gf_mul(d, B[i], m);
                }
            }

            if (2 * L <= n) {
                L = n + 1 - L;
                hqc_gf_t d_inv = hqc_gf_inv(d, m);
                for (uint32_t i = 0; i <= g_deg; i++) {
                    B[i] = hqc_gf_mul(T[i], d_inv, m);
                }
                b = 1;
            } else {
                b++;
            }
        }
    }

    memcpy(sigma, C, (g_deg + 1) * sizeof(hqc_gf_t));
    return L;
}

/* ------------------------------------------------------------------ */
/* Chien search                                                         */
/*                                                                      */
/* Evaluate sigma(x) at all alpha^(-i) for i = 0..n1-1 to find roots.  */
/* The roots give the error locations.                                  */
/* ------------------------------------------------------------------ */

static uint32_t rs_chien_search(uint32_t *error_pos, const hqc_gf_t *sigma,
                                uint32_t num_errors, uint32_t n1, uint32_t m)
{
    uint32_t found = 0;
    uint32_t ord = (1u << m) - 1;

    for (uint32_t i = 0; i < n1 && found < num_errors; i++) {
        /* Evaluate sigma at alpha^{-i} */
        hqc_gf_t val = sigma[0];
        hqc_gf_t alpha_neg_i = hqc_gf_exp(ord - (i % ord), m);
        hqc_gf_t alpha_pow = alpha_neg_i;

        for (uint32_t j = 1; j <= num_errors; j++) {
            if (sigma[j]) {
                val ^= hqc_gf_mul(sigma[j], alpha_pow, m);
            }
            alpha_pow = hqc_gf_mul(alpha_pow, alpha_neg_i, m);
        }

        if (val == 0) {
            error_pos[found++] = i;
        }
    }

    return found;
}

/* ------------------------------------------------------------------ */
/* Forney algorithm for error magnitudes                                */
/* ------------------------------------------------------------------ */

static void rs_forney(hqc_gf_t *error_values, const uint32_t *error_pos,
                      uint32_t num_errors, const hqc_gf_t *sigma,
                      const hqc_gf_t *syndromes, uint32_t g_deg, uint32_t m)
{
    uint32_t ord = (1u << m) - 1;

    /*
     * Compute error evaluator polynomial:
     * omega(x) = (S(x) * sigma(x)) mod x^{g_deg}
     * where S(x) = S_0 + S_1*x + ... + S_{g_deg-1}*x^{g_deg-1}
     * (syndromes[i] = S_{i+1} in standard notation, but here syndromes[i] = S_i)
     *
     * Note: syndromes[] is 0-indexed: syndromes[0] = S_1, syndromes[1] = S_2, etc.
     * We define S(x) = syndromes[0] + syndromes[1]*x + ... + syndromes[g_deg-1]*x^{g_deg-1}
     */
    hqc_gf_t omega[RS_MAX_G + 1];
    memset(omega, 0, sizeof(omega));
    for (uint32_t i = 0; i < g_deg; i++) {
        hqc_gf_t val = 0;
        for (uint32_t j = 0; j <= num_errors && j <= i; j++) {
            /* omega_i = sum_{j=0..min(i, deg(sigma))} sigma[j] * S_{i-j}
             * where S_0 is defined as syndromes[0], S_1 = syndromes[1], etc. */
            val ^= hqc_gf_mul(sigma[j], syndromes[i - j], m);
        }
        omega[i] = val;
    }

    /* For each error position, compute error value using Forney formula:
     * e_k = X_k * omega(X_k^{-1}) / sigma'(X_k^{-1})
     * where X_k = alpha^{pos_k}
     * (In char 2, negation is identity, so no minus sign needed.)
     */
    for (uint32_t k = 0; k < num_errors; k++) {
        uint32_t pos = error_pos[k];
        hqc_gf_t x_inv = hqc_gf_exp(ord - (pos % ord), m);

        /* Evaluate omega at x_inv */
        hqc_gf_t omega_val = 0;
        hqc_gf_t x_pow = 1;
        for (uint32_t i = 0; i < g_deg; i++) {
            if (omega[i]) {
                omega_val ^= hqc_gf_mul(omega[i], x_pow, m);
            }
            x_pow = hqc_gf_mul(x_pow, x_inv, m);
        }

        /* Evaluate formal derivative sigma'(x) at x_inv.
         * sigma'(x) = sum_{odd i} sigma[i] * x^{i-1}
         * In GF(2^m), the derivative only has odd-indexed terms since
         * even coefficients vanish (char 2). */
        hqc_gf_t sigma_deriv = 0;
        x_pow = 1;  /* x_inv^0 for i=1 term */
        for (uint32_t i = 1; i <= num_errors; i += 2) {
            if (sigma[i]) {
                sigma_deriv ^= hqc_gf_mul(sigma[i], x_pow, m);
            }
            /* Next odd term: i+2, so x^{(i+2)-1} = x^{i+1} = x_pow * x_inv^2 */
            x_pow = hqc_gf_mul(x_pow, hqc_gf_mul(x_inv, x_inv, m), m);
        }

        if (sigma_deriv != 0) {
            /*
             * Forney formula: e_k = X_k^{1-c} * omega(X_k^{-1}) / sigma'(X_k^{-1})
             * With c = 1 (first root is alpha^1), X_k^{1-c} = X_k^0 = 1.
             * So e_k = omega(X_k^{-1}) / sigma'(X_k^{-1})
             */
            error_values[k] = hqc_gf_mul(omega_val, hqc_gf_inv(sigma_deriv, m), m);
        } else {
            error_values[k] = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* RS Decode                                                            */
/*                                                                      */
/* Returns 0 on success, -1 on uncorrectable error.                     */
/* ------------------------------------------------------------------ */

int hqc_rs_decode(uint8_t *message, const uint8_t *codeword,
                  const hqc_params_t *params)
{
    uint32_t n1 = params->n1;
    uint32_t k  = params->k;
    uint32_t g_deg = params->g;
    uint32_t m  = params->m;
    uint32_t delta = params->delta;

    hqc_gf_t syndromes[RS_MAX_G];
    hqc_gf_t sigma[RS_MAX_G + 1];
    uint32_t error_pos[RS_MAX_G];
    hqc_gf_t error_values[RS_MAX_G];
    uint8_t  received[RS_MAX_N1];

    /* Initialize GF tables */
    hqc_gf_generate_tables(m);

    memcpy(received, codeword, n1);

    /* Step 1: Compute syndromes */
    rs_compute_syndromes(syndromes, received, n1, g_deg, m);

    /* Check if all syndromes are zero (no errors) */
    int all_zero = 1;
    for (uint32_t i = 0; i < g_deg; i++) {
        if (syndromes[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (all_zero) {
        /* Message is at positions g_deg .. n1-1 */
        memcpy(message, codeword + g_deg, k);
        return 0;
    }

    /* Step 2: Berlekamp-Massey */
    uint32_t num_errors = rs_berlekamp_massey(sigma, syndromes, g_deg, m);

    if (num_errors > delta) {
        /* Too many errors */
        memcpy(message, codeword + g_deg, k);
        return -1;
    }

    /* Step 3: Chien search */
    uint32_t found = rs_chien_search(error_pos, sigma, num_errors, n1, m);

    if (found != num_errors) {
        /* Could not find all error positions */
        memcpy(message, codeword + g_deg, k);
        return -1;
    }

    /* Step 4: Forney algorithm for error values */
    rs_forney(error_values, error_pos, num_errors, sigma, syndromes, g_deg, m);

    /* Step 5: Correct errors */
    for (uint32_t i = 0; i < num_errors; i++) {
        if (error_pos[i] < n1) {
            received[error_pos[i]] ^= (uint8_t)error_values[i];
        }
    }

    /* Extract message from high-degree positions (g_deg .. n1-1) */
    memcpy(message, received + g_deg, k);
    return 0;
}
