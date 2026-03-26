% libpqc-dyber - Post-Quantum Cryptography Library
% Copyright (c) 2024-2026 Dyber, Inc.
% SPDX-License-Identifier: Apache-2.0 OR MIT
%
% KEM (Key Encapsulation Mechanism) class.

classdef kem < handle
    properties (SetAccess = private)
        Algorithm  char
        Handle     uint64
    end

    properties (Dependent)
        PublicKeySize
        SecretKeySize
        CiphertextSize
        SharedSecretSize
        SecurityLevel
    end

    methods
        function obj = kem(algorithm)
            %KEM Create a KEM context for the specified algorithm.
            %   k = pqc.kem('ML-KEM-768')
            arguments
                algorithm char
            end
            obj.Algorithm = algorithm;
            obj.Handle = pqc_mex('kem_new', algorithm);
            if obj.Handle == 0
                error('pqc:unsupported', 'Unsupported KEM algorithm: %s', algorithm);
            end
        end

        function delete(obj)
            if obj.Handle ~= 0
                pqc_mex('kem_free', obj.Handle);
                obj.Handle = 0;
            end
        end

        function sz = get.PublicKeySize(obj)
            sz = pqc_mex('kem_public_key_size', obj.Handle);
        end

        function sz = get.SecretKeySize(obj)
            sz = pqc_mex('kem_secret_key_size', obj.Handle);
        end

        function sz = get.CiphertextSize(obj)
            sz = pqc_mex('kem_ciphertext_size', obj.Handle);
        end

        function sz = get.SharedSecretSize(obj)
            sz = pqc_mex('kem_shared_secret_size', obj.Handle);
        end

        function lvl = get.SecurityLevel(obj)
            lvl = pqc_mex('kem_security_level', obj.Handle);
        end

        function [pk, sk] = keygen(obj)
            %KEYGEN Generate a keypair.
            %   [pk, sk] = k.keygen()
            %   pk and sk are uint8 column vectors.
            [pk, sk] = pqc_mex('kem_keygen', obj.Handle);
        end

        function [ct, ss] = encaps(obj, pk)
            %ENCAPS Encapsulate a shared secret with a public key.
            %   [ct, ss] = k.encaps(pk)
            arguments
                obj
                pk uint8
            end
            [ct, ss] = pqc_mex('kem_encaps', obj.Handle, pk);
        end

        function ss = decaps(obj, ct, sk)
            %DECAPS Decapsulate a shared secret from ciphertext using secret key.
            %   ss = k.decaps(ct, sk)
            arguments
                obj
                ct uint8
                sk uint8
            end
            ss = pqc_mex('kem_decaps', obj.Handle, ct, sk);
        end
    end
end
