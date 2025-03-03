// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x085f3a00c4aebe3a048a82fb962b2ff0b8a19269611692be0a9faf64b0394abf), uint256(0x1051b5fcc9d478157c3c6c7c5b87a3ae8399e079794af8a13599c51f4ec29b6b));
        vk.beta = Pairing.G2Point([uint256(0x0f3c495366c2e332a3d5ebd4e0b32374ec4c9f8468c4cf06226052dcff214c5e), uint256(0x1494f226ae6d2fd866f9ffd557e2f50323b4245fd30c82b654ea97823537c030)], [uint256(0x1c307ffbfbb6e96daeccf5471eb3264c36cb57573e695ed2a9ea1fc428db1817), uint256(0x1c9c005c6be3aeaae6ad7923f3bbd65ab1d1f8866c4c1d7eff019f32c318cf6e)]);
        vk.gamma = Pairing.G2Point([uint256(0x070768ff1dae22c354d9e1688864c773565d7ab4f310620d3122eb2adad104f9), uint256(0x19d163f5164281058fa66e6b48a1dd8ee422e1d57e2ab2b366ca6e334b92eaaf)], [uint256(0x18dc9eace888bd29442766f8f9af9bcd024de1ee625e0c75f1fdf05ce4f86abe), uint256(0x242a78c45a47ce1d29b94e53c3a80526442743cb5f08ac201a214d0ebde41b40)]);
        vk.delta = Pairing.G2Point([uint256(0x2f9dae002769d8f9f67419b1cf4cfe4f383cd580bdfd5543153695812a616872), uint256(0x28aed164b7d68c763e01ab852477fc6e91e960df5e189cafaa856aaa0bb40bb0)], [uint256(0x2f9beb398d52682801e6aa1ee062b0e305c21b9d80c3143eca45c2fdb59c122b), uint256(0x221b632059c22acc084f18e08b2f62ca65b66235ee7e83ba0663355be082a692)]);
        vk.gamma_abc = new Pairing.G1Point[](23);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2b9a09f357341fd100ffcee9e2c216ef7baa6475b02b6b5e1084bdcfed01b429), uint256(0x1c820d8988b4237d70cb73a2fbb13af3da610882fb5d743180bb06008875d786));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1370713d0d5412a25274fd7260d4a35f5cf9ed44c9b63be18db665fb944ba158), uint256(0x19a5e7e2c849aeee3b02831d6cf7a3a09ea61a4367e0c54d0a4ca3c0258c199c));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0cb38cb0ce46d41934df858c723b3045048f17970f8e8a526e951cda113006ef), uint256(0x119013c1c32e0b8780ed58d6b43a0750ad4555e18a1df5a7b7e07c224d2f4d9c));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x23ab6287687629e5912d936949d698402109e6d7da49ebb2fc201112a066c159), uint256(0x20ca62451eba32d18a0e6b168ffe2a5d35cdea553ac788115bdbf442bf496ad6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x039abf48b4b6f5891b5b7dc01c2ef0319b030e939d0505a25fc0bfe1211b4e74), uint256(0x073576923a3793633dcd4fdd1976ee048c42dbe10bbaeb42d27d228b25a35dd5));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0dd84361af1f50aa124c667b514ce1741bdb5897da7b3715f56de4f183234528), uint256(0x2bccca13e090f1a57cc1e7124ef88c56885b37b0d1efbdffc01d64cbd72bdd10));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2819d3c3f8a52fb4006647321844e2a4aaa99a5b813202727095ecf1c9c9b80d), uint256(0x08451292db132568e3882608c12548c002e2afd5689c9aa02c6226b87b560184));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2cd9a58a88cc3814c4f3b3a4a4b19390c9fa252f4c3f1b6121a71dcf4f0f6965), uint256(0x28af45a7ce9eb4859317598e857f902c44f210b8542a79f6c6f4eb8fafde0eac));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x00ef4bbe1f6a79285f8c61169ad9ec744f0419a8699852fa2986b3994d86f6a9), uint256(0x2846d213b980d94db455febe308f402ac7f88922f4cd1015bb63387e3bfa627b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1b2e575257e43b42cc396556e43e73b5f7f23e6412ec236703d034f516e3f437), uint256(0x08414cd6137c3db99394f2bc393dc4a5da6c91c5072aaa6ab606997366bb110c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0cc1e82fd7aeb87f178954748b9d7a2127583d6cc9fae25047fdae961c1ebea5), uint256(0x0b9905d75da96cce6d4f9bb7a72c7c32c95d7866e7ae11e3caaab75149322596));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2a917c8248173e30da703d0508e7cc16bff81060cacf16d4e02babda789d90d9), uint256(0x1e30e7fb0c5c4dca8dc45c3a25e6ecb51e01c68055d66fa447508a6a296ed639));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0f3d4c891a2254ac591ce2d2073ed0fa2e93bb0cda0579f3be82426619e77136), uint256(0x268defb65de128402f2579ae00443cbc69220f1e92819ba1a6a6673bcebc0bba));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x110582fc5e7a20329f81e9ae884cbd4d758598373be1d44a11dbfb47c1087a62), uint256(0x0cc0c3ee0af32fc9d2fe3438c43a8c2e55f70e6a03e4ade98a0fac77761149e6));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2685f5509243efcccb2069b25ace78b6214becb62926381ff8d748df51b03610), uint256(0x081173439c02762153a05bf696975d7bdcd097407c5239af2037cbd5908ea772));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2123cca2dc4991fd4694dce0ab1fcc0f2e19ff807b74369a575a870cd8ddbe6e), uint256(0x18163dc9a21ed35968339bf7ed69aff9277f71345270d06a2687ff5e03160b84));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x3026899374f4c2d71537674525f75a3eab69bf84942f081a8d1ec371ded3d8f2), uint256(0x004832565b7a11e45702c459dc67ba290573c8b2d3a275cb5428f86b5f714b00));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x144d7b059d2c31d6c6a86d6c33c613a7baff05ffcc94aca7953687e79f01430a), uint256(0x1449a0733dfed37cd406d18880cebdc64e44f49d95c755ca26b9ec979bf72892));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1bee2a324e862dacdfb00931f30394bc0c9422f19e70867593b6fbbf2b8c6e46), uint256(0x157687738a1a32304e282c1a8afad75b5a8beffed9e7f4c6335b86054eb773db));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x295eb52682e55ef8868a2161de7127cdca674aac4b3960c9a9d5565c88bac54b), uint256(0x298d58f916b3687f1b3489814a340414150c47d63466a492abb4bb0265883abb));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x13f5ec18d9399849143328121b103ab95cb7715cf605f17001870cd1bf3724b6), uint256(0x2abacc48ae4e17a8b094059a7028dfcc3822d11a03b7d2512834872c7501e813));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x21d290862ced47c14e864c53c4a4c3164dd64a33258b916d3b9ebcae0a909fe2), uint256(0x16d123ac1aa0097c8986df86d8f509f76f4011b6ee29d64db9008e02132f2d50));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x130306eed36ddd5090e713db03a8f8b066f36d529f97901992d19e0b68571f98), uint256(0x2ff02425c239524b454823a15af1352931edc304d8dd294947038357705d2f21));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[22] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](22);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
