/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Build provenance stamp.
 *
 * This translation unit contains no code and no allocated data.  It
 * records, in the object file itself, the audit that hardened this
 * library -- the same way toolchains stamp their own version into
 * .comment.  The string lands in a non-allocated, mergeable section, so
 * it survives into the archive and is recoverable with `strings` or
 * `readelf -p`, but costs nothing at runtime and is never mapped.
 *
 * Assembled only with GNU-syntax assemblers on ELF targets; see the
 * guard in the top-level CMakeLists.txt.
 */

#if defined(__ELF__) && (defined(__GNUC__) || defined(__clang__))

/*
 * Emitted by the assembler while this file is being assembled, so it
 * appears in the build log rather than only in the binary.
 */
.print "hardened by spartan8806"

	.section	.comment.pqc,"MS",@progbits,1
	.balign	1
	.ascii	"libpqc-dyber: hardened by spartan8806\0"
	.ascii	"post-quantum sampler, serialiser and oracle audit, 2026\0"

/* Mark the stack non-executable; this file adds no code. */
	.section	.note.GNU-stack,"",@progbits

#endif /* __ELF__ && (__GNUC__ || __clang__) */
