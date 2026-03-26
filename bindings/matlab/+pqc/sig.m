% libpqc-dyber - Post-Quantum Cryptography Library
% Copyright (c) 2024-2026 Dyber, Inc.
% SPDX-License-Identifier: Apache-2.0 OR MIT
%
% Signature class.

classdef sig < handle
    properties (SetAccess = private)
        Algorithm  char
        Handle     uint64
    end

    properties (Dependent)
        PublicKeySize
        SecretKeySize
        MaxSignatureSize
        SecurityLevel
        IsStateful
    end

    methods
        function obj = sig(algorithm)
            %SIG Create a Signature context for the specified algorithm.
            %   s = pqc.sig('ML-DSA-65')
            arguments
                algorithm char
            end
            obj.Algorithm = algorithm;
            obj.Handle = pqc_mex('sig_new', algorithm);
            if obj.Handle == 0
                error('pqc:unsupported', 'Unsupported signature algorithm: %s', algorithm);
            end
        end

        function delete(obj)
            if obj.Handle ~= 0
                pqc_mex('sig_free', obj.Handle);
                obj.Handle = 0;
            end
        end

        function sz = get.PublicKeySize(obj)
            sz = pqc_mex('sig_public_key_size', obj.Handle);
        end

        function sz = get.SecretKeySize(obj)
            sz = pqc_mex('sig_secret_key_size', obj.Handle);
        end

        function sz = get.MaxSignatureSize(obj)
            sz = pqc_mex('sig_max_signature_size', obj.Handle);
        end

        function lvl = get.SecurityLevel(obj)
            lvl = pqc_mex('sig_security_level', obj.Handle);
        end

        function tf = get.IsStateful(obj)
            tf = pqc_mex('sig_is_stateful', obj.Handle);
        end

        function [pk, sk] = keygen(obj)
            %KEYGEN Generate a keypair.
            %   [pk, sk] = s.keygen()
            [pk, sk] = pqc_mex('sig_keygen', obj.Handle);
        end

        function signature = sign(obj, message, sk)
            %SIGN Sign a message.
            %   signature = s.sign(message, sk)
            arguments
                obj
                message uint8
                sk uint8
            end
            signature = pqc_mex('sig_sign', obj.Handle, message, sk);
        end

        function valid = verify(obj, message, signature, pk)
            %VERIFY Verify a signature.
            %   valid = s.verify(message, signature, pk)
            arguments
                obj
                message uint8
                signature uint8
                pk uint8
            end
            valid = pqc_mex('sig_verify', obj.Handle, message, signature, pk);
        end
    end
end
