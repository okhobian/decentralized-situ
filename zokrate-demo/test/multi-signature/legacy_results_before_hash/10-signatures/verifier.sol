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
        vk.alpha = Pairing.G1Point(uint256(0x277c7f164ed30dee97ce7570933a143d83c95927ea93c8ffdd9088f7f1446265), uint256(0x2291b71f8b0ac3bc1c9ffd841da52718f8154791fef5f54e603a73da32e550f5));
        vk.beta = Pairing.G2Point([uint256(0x1e9668e3dead2928712a3af2976651cc90d3a76d373b10c4e0e2dbc1af0a09ab), uint256(0x1f6b82ddf962f619e35f9cfada4c7e95bbcc65dcde90b4bb0f1bb76c530ba3dc)], [uint256(0x227da71968bd973a3b60ccccaefab901607b822c65348cb4c08411f58432e4a1), uint256(0x105e0c1c7167037495cc112ae6f4e4b7ef0f53ae3798cacc2cee88482c4d94f1)]);
        vk.gamma = Pairing.G2Point([uint256(0x106ff357ad67666c5f82605bc1731844eea34f9e8937a3a9e06c4c2abdab139b), uint256(0x0111144e89e22407e34e7451c4020b9968fe153ed1dc810a5b3e2a82956c1bfd)], [uint256(0x0fd44d65565d2759fe1ea60a092e87ce179dda1e98fdcfe596904feab32b887a), uint256(0x245e107ab3d40e803725c23b5380c145305219df3452bffee7699af6b194a58a)]);
        vk.delta = Pairing.G2Point([uint256(0x0972f4cdff7302b07f88778af55ab5b4dd7e1fefe0b32385c61e80da53b46076), uint256(0x1cc57ff2f1de21ebfad232f77fe7858965e5116025d0820480a0d6bfabb9c298)], [uint256(0x2e2b01a3344c24b7a957133330bfececee7ef3f2bcbb59b96b224831ee9fd2f1), uint256(0x14f8d6a5de94c948143710e0a65ce30d868ff90f6b2e30c1ccb4c16ec3a68beb)]);
        vk.gamma_abc = new Pairing.G1Point[](213);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1c57c6d49848f4d4b459114bbdf0026bf54edd219d4a2fe237f786d64c75d921), uint256(0x2ea9af13a9d2b02387d09425de666de68bd668a1300d4f5c3134ccbb17efe294));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x264707d873bc006cfea5272336dc0c364e96b085ddc49b5625dc41b127f9fef5), uint256(0x171625c369200f1565f54f4fee577eb8ec327e8667d801a8751f5ed774e5c02b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2a31b4bf49558a404bf7cc1ac0ca25cda7b9bba8d8ef2bc8ca28e9abc60a0a88), uint256(0x002cefef06aff073395a41966ae35838b90c9a20055283cec1f246b4e02cb552));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x063f0fa20b02c893ff0bce252abaa6d55d5c4310360820e928556c859f7d59f1), uint256(0x191b59aaca7bacddc3bd2c6cdfb863e264417371b5a4618e122f29b521d36cff));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2faa262a7b0d26fd7c51f3811dab9dc7175a8e7c6f2408727504ece254d5b00f), uint256(0x17f3b478f9fdc35a160b86887050c9e2bbb36c1cf180f92f202019504402669e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x189728d001c12a0d9cc9e163f120bd498f0b96a0ff66cd45ab628bf4b80ddde0), uint256(0x256f351d020871046a4acb28e5857a4c986389e122711e4ef3167ad6ec66615b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2db37b79b0f7f9be1fcc59455befac9946b7748d27ef04c533e88be5a92997ca), uint256(0x03b5041a71f184dd82878ff7b5169b5df3d186a58c2ef8435688f2c649546e37));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x09b0270a8a3713d038b1aa37c81b94a5c9f8fae176edc58381e110132f2f881d), uint256(0x2ccffb13b3978ba6b9b1d73de2823b6a50c8af38d54c22a182ecbb8e67d7e2a9));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2d7e2561c6d7723fd7c2f71bb28fa26e6db155239877790a0915bf44f548917e), uint256(0x0526be63cf0b85ea034b6ad72965ae091f9634e5ebd109ff001c467dba13d5fb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0b10b375ebe57f917803f123e2f43a4028f23faf020b36576cc94dfbe5a88075), uint256(0x2434b926918ce8a9f45a3dfc3ea8ee11eb2a7c1c512ca66f8bf435154c7a8a76));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2f83530912a4f779dae46cf3ba1f675569d2b46a4e236b45f21510bc27235f21), uint256(0x13bbc0aae3bd684aa5a8de43f9bfe3cde099cd6a0efe2d110ddd7d2ead8bf8b9));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x286eaf5cdf9485b2e4df69456c6b0b2f57849d713fa5ed73bbf6f19dc72a9904), uint256(0x213874092e7891847ad607a50d84b1defa2e3144403406d5e3a4b5443b8021b8));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x208c77b9c96980687131706fb5905c19f16c8434f975db64d9ff558c95dc86d9), uint256(0x260c1b26dd07418b6a2855d2a1b3a1aa29612a29a7a0753b7ab821822f49badc));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x072e7b4512a496fda17b3680a8ac2c54af116a22b3f28a6dba72ae1000907ba5), uint256(0x039d6fc88f0098eb0923cfdff793296b1b8490b53571f3f39c1265aca4655f18));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1fc5d89e3e50b9903c4b4c4e0c026e35313443edf62365f3ba5d267b8ddc9329), uint256(0x0b22f71ddd8246ac58a2fa4c8bb27342d64fe1bcb6f3c6939cf1317103536d6f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0e8c1ccbdb1a2fe80d156568d85787758b3c4655648559464f6c8a6d6ff8d1f3), uint256(0x1c8596d9c27e531cde1a074dc20b395addb8f0602b6e76ff5443950db1ff7415));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x037a08c68a0308f02809fa876024c0f76240f666631a8d78db9c5fe2fa53a851), uint256(0x03e4d00b124ffc4632a556366e634d941fc01f1c70135963dee96ac8d490507e));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1707f9214d92f9ea3c5be4e083d01ee8ced8a7519a1a1071662356fb3e2621d5), uint256(0x11672c803215d04649eb68013d5b3af98627a4f20541699dba91eb9af46c6a1e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x016cbe9ef5b557bc5b3641fedfa5e5ac2bb029991943959b044af38f9a6c0d5b), uint256(0x0b240920770970219f926af30c2f0b8d44b5ebd1a8c32bba81943214dbc39657));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2ea06dfa98e31c426e44efbf06313bc036cc3ebe5b968aa598f00d757836977e), uint256(0x10094cf1d477e8c0158f43145bbea420f3f7a2f3d63545939b446ddf8971f41e));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x20047749bdccaee2ba984eed7f5eaf5efa08e86d0552fabfd9af5611e9c6e919), uint256(0x296282327e236affdcaa4a272f44089161168a53839ff2fe69d6b29f78865a30));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2cfecde95529ff839e519651305caf869ea971406a412f843152c68fb481b8e9), uint256(0x2c6a04a63de07fbb2a4ee0690069925fb42314958855b88125aa324969089c85));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2882d70164d6b9d5c5773e858dd7125f30c18e7c286445268d3c791134b11730), uint256(0x1fe43ee1088ca14a9efcb57e4fa79190c922095d242a367a1782ca3f247dc95d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2ed15fef00c5418816be6d47c5ca2b6d36b2150fdde7d216b07c409fc97a6aa7), uint256(0x0154f38b1ffbcbe5d26277750bbc8d48ab04ea01f1bc285dafb12c2888e2d0c9));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0855c338d1ac27bd6b67bdf2496ffa57d8b4104929b85453eb9025e47e46430c), uint256(0x183dbdd285aa40ebaa0f98d3e6cb271551df4e2615470964aa54374f6c3a6629));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1efc3d9faea1af615cd113f3e98e24c74e0cdadaf066b4d20d70fbd284bf433b), uint256(0x12dcc6a5ee4e0214c1fb415e56191b7df76f8d3eee15e3f1b5809934baafc78b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x21d87abb9fc35e690a04d8e157b9b2d3638d5ed0b9ce4adfb12d11134cefc7e5), uint256(0x2d2d72814303db2949c9f87195fa5686f3a1d00a3ac53083395e7f139edd8310));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x139a3b51f3b32df0501854a567e6f61366721f2052eedeb96277f0679a7ed5ca), uint256(0x28b4dd816d0a34c7a5e701148d5b69b943b8674a7d93244f34e770a80dd091c1));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x202a5b6ec992ca729796d310a777482f090eedf47fdf6f68651a65edae8a52b4), uint256(0x2d855c2caaf43759b53800cef3330107fd191dddfe26ea7245d0bd6a26aa3f15));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x169fe28d1ee6a7d68a10c29501430cd18b5e0d12ba9af11413870b3857b10087), uint256(0x2d6f106e17ccc19c6119a82367d640a708bc63b229f1e925a2fefe9106daab52));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0cf14fe4aef6a0f8b8a0158f9dc7b052434141560a9d72b3c720e86af451fb8d), uint256(0x22341179918152373b8108da762b7851a234376f1f210e9565987fe20d66486d));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x102b85e0c50290bb02a1fcf242dbfd2bea6848adc0e4b5f27f8ba27ce4980481), uint256(0x303c0d0d0b2b171cc9c6743fe1a5092404b1d7eefba606808e5504b488c4588b));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x288cc3b7ea149f59e0e5ffa3cca10de3fcf3a3a26f485343c2ad1becf08869c4), uint256(0x01d26fd8a859e67873a4505c7786cfd3f69165a72023fda0e48b5883fad84f59));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x28ccdaaf9bc70204290f203e04a055656b44f70590f7453730618769f855961c), uint256(0x156f6061763197e8c772ccfe9bfd2c4b4616ec4fb4e9973436c8b5866746ddc5));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x18e44cda6edb773f96c6119abe918565b6ac734379525d89e0d6c209e5c527f7), uint256(0x07a9e7ca10aeb70329522df7df9800e10cba12300fa375100ad6b431c2a19740));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2906bb6c6f930b14b79e8f686a60d590536c10056f29340342cf6cff4c4f1066), uint256(0x2fa82eb132fd8d68b1c818c9d72b391fb92a3e100f32cd99496ffd7f058608b7));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x109d2d16a48e21720d0a10c75d5efe8d98c722f827bc8ce53f24a06aa8c75ecf), uint256(0x1041dc3e54bea01daa312500fe95b614b2952140584de419d040f71a49e5436d));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x028b0a878c2139bb43fc4f1f03681d031360388fe384e57775ffb7fa66f9213c), uint256(0x2fb4ce201f7092fff84b7a45a917c8856a2964abb4ae123eedcdc0d3ee3e59b1));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x00e543ed0a222fd97ae614a7e2604f48f30ffa6b2fc5b57c4401a029fb130bfe), uint256(0x1a3ed57b8bbcf4b4fe0e45e2e61c82daaca23a30c565a60fe4cb759fa9a3063a));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0796893475485b48a3eabf0cb4b8949d98a4d489b23555e1b91fe7ef3f5f4c5c), uint256(0x12e64dd8e1796aa36a7d676535c447c2a310c1bd9885114f211bea266a8592be));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1ea6d304b3091c2ceb21127f5bbb8b942cf99770419b4aacb25c7c8f4cc2b5e6), uint256(0x1ff8cd176b18661841e50f6a9af1def7ed0eb2b118c923ef974c48f80fd8d79c));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2d8e019c86b7f3b01105f8627af460f247768678559e9b32a042f3f2dbb5fe08), uint256(0x08b1cbd8d1833ba4de627ddeb26e89cc251f5b48560e80a0442f99454f87d9d0));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1580b6c3fc055c1c15b906d3dec0c67f7ba03e6b78ac18140ca3fdbe966d7ada), uint256(0x0a227c76de47ccd6ff53626e6e6199c94a21fc17de17124a622dc32dc0dfa4d7));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1ecc401febd327f78f27a216092b9af6ffd65ea67527e3e046a3cba33a3e6cd1), uint256(0x17a3c4bf4f6cf2db8acf688a9ae4ceec646135627aba28b22f173bc8c8aecc49));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0fc59a66dcf3d6150c2308b7dc2419d401079384d3b1edad845e3b7941d546fa), uint256(0x0cef69d657897da51db3c80fc99a190898822acebdcdc88e828e25add5dfc5bb));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2f29c873e5dcad22fd591cfb2cf6be856602e7c4031e74183b066af4261ec41f), uint256(0x2eb822e754e3dd375c0b86d9123fdf0a86102e9c1878fa23f1d67856d4db28c5));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x12c4ea2f9ddb731b0d9598ac7d8e36c33e26829b2dcbed1798a292708cc7c067), uint256(0x140fd1434e6719db952a9ef2a424c222ebb5eb091936996bc03e05144f1e5578));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x15aa3cb8551cbb3d4eefc7e0d35c41972df9859369a81a5e29dc1c4afe764d7f), uint256(0x198bfa9532c90a5c0c46847c3bc1c0207a0a4f9e887e36464b8c41fdbe6b0b49));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x19c4fa7b19829e53da7dd4a85fb47967d6b2bd4f25bb3fd68443a265bd2557ba), uint256(0x00f35ab614e7070d42826db78db17599d92be8a09ba4a4472e35ff1599e118a4));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2e517e43fb0e163b114b6f9586f72e48c49bd1b4db704d20ae606ff25374928e), uint256(0x0597adb285d6e8ddb81e8b42e2f2471c68954c72a1f0ba23e3679b74f637d122));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x27123b5ad804098cd5ca0a48e807fdf3ca8aed6271913c8cd2c2b95b279ed02f), uint256(0x24f0866170287d1f8183838e20e3706af632233b63e433ad86a4063f4f96586c));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x10081239fcc500d04c3558db946bfabbd01947a0f387910b5ca86e46ce33c0ed), uint256(0x1d714b6853d5c4734e3c977d8bc0950c2e9910708080be2764fb9d4fd70b4ed6));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x271eec32ed2a8a8c2b86024a2e8c829fdcef67e1961c195f32e21f2729104cc9), uint256(0x1bb697728c7a6789e5a21f105fecdc9c8b5fd3b77366419b67577977c4622226));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1dc31968ca7fc1d22bb0167510f90e30d0e1b798afc7d04cd645da5d8b594893), uint256(0x1aaa994c8f66ebc9013192da705a2f09bd74847bf8f3c563ad5f2bbcde2b6778));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2caea4d60518244b9e5ba9072bc191e1301094d542a958b4ffd8e81f27638d92), uint256(0x23b1c582a392add6e2bcf5df59b1f77c10252454d3cb37b4202a465638f1dce4));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2023d1b54c755dce1629b2bb718f1deb66ab5310e03ba7e93192e84181405393), uint256(0x2e915a654d1dd1915e2f965960c1cb21a71c0a1fbc69ff766ab8b39b4284b691));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1380c1b8fb732e3564bf5c3f762029492abb5667207d499e3c750d30285af188), uint256(0x0e6eea85848688caaba6172c8fceca73eb1a496aefca62b9d36844e175cb39d1));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x208c0c0bbe49b9bc9f0b77439e3e5646eb3dfc2eb55164fb228fb29fafe4f8ef), uint256(0x274c6437c9616727c0fdd27a8d499b6c6f9da107ff569f5e0c781da9f7296478));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x030bf3654b5ef59b31f69df0822228cf0d9748f34a138b12d7eca5235f4d5414), uint256(0x1361135b173c2ccd5269a9eb43e4f1303c36e58a947daab15bd8afdb8ee73522));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0acf6c7e01e06c8b68eb3c4a4b59f4255a3e9e61decb611d806172820b347f6f), uint256(0x160529899b51a281bcdd656ce9ac63276be6460e88a2e4979ccbc4916fc84afd));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x048025e2a2cbd19683517948e873423935feef28954a119cbb8b2da115c67636), uint256(0x27622fac13496ed610bc9b3ba5c0caa28c6d7442e41a822a2b73df3c0db5a8a8));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0645604039cacd874b7c6621500ca2886c53e6b0698da4655051987a3ef17f51), uint256(0x10faa3d8261ac924536e89f93e9da52083e07653b4f4a3a2f7fcfe1b24a23655));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x20d318b8ea71bdcf6119770ed89e50b8dab53cbfcf1bdbb0c3004552488cb6c2), uint256(0x2f9d071db25574dfd6dc5d96cfa0ac8ab531dada8dd9dd409d5484abe041128d));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2615e5003f77b59931445cabbb1ac33283d17b0a7c94819a04238a61144ec2c2), uint256(0x1c432bf60fa7f056d5da435c1b0632616fb33cd94b12b361fc86d704de920d0f));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x037feb8dc0dc0057d5c2f19b60798e980ad0c0e5232c9f30f6b03d29183015d7), uint256(0x040f32273a25b1c5ce011023858fac15d25942b7aa6ee176082e0efb3315a6c9));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x02c0349ceab1284dad3554848030ea1350585e125aaf49eca5dc045b20904ac5), uint256(0x01fbd1d7298f51630794ce09693b627a956ec9b6bf46ebce278c6a38595aaa54));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x221c59cbd2871e7a8d2a427b940ac4a9de335527e626f67a07c954be12dc7d25), uint256(0x16ca46cc265fa682fdcef8ccd09b45de6d4447d521870e16b7152370952a2bd9));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1b8a4910846c00ea2a182a228cfb813c0c433a43d27455b488bd50bc48c75660), uint256(0x0993a0b2205c389970f8afd9372f1ba5754819035a53690836f40f5cdacd838f));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2b001c1767457064be5d5f853ea710712f00e52a3881f66eca93240a6293700e), uint256(0x20fc7a9572cd7f365171273d9220e0dca28ba0a1641b5fb09ee67be7d782585f));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x28ea6737d580d34b4c3281940d0542f1774ddd02978fb31917a00655427eae04), uint256(0x2094f6f23aed6b40fe3b15e0489d907cac6480a359b7970282b84f3b350614a9));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1b458054b6b850520ec1878987b2224d18ae8b7dd7655dae0e2558e9627d184c), uint256(0x117f6071acdc358415a7c040e318ce1531142f2a44e5ad54f7a507d6f01ca4c8));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x08d8be00be1c9d62c08e4c276ab591cb7a8c04527a88ffde9759c00674168083), uint256(0x0a59cbbc91b1c8c0ebb1f2e39c2d5605861f3a06de71e25cb5571e91e17f2b0e));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x118ddde50c8d77b9c9f7577341c3c1122d4a2243a5003171b570c8aedc7cdcb2), uint256(0x15e86b2a3c83a578214b8db76b6d67db7e1da23571ae1e4de69fa7b77bf24a0b));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x15a9bc14ddcb6622d94297b6a0b5fc4c464a63a29c785927c71bc10cf9da0f1b), uint256(0x013421ec1140b3261f5e5ccae42cd771f10c892600afd4d0b51786db948ec2df));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x215a148199bfd4f457da83f24d6cf388b0f278b4287a02a257ab9a5a12b989d1), uint256(0x2459550aa56b4e522200042449cabbcadd9bdffcb7e64566c4426b732e74920e));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0bde0b1449b6f6847fcf5700ed7235324e1774dcf95e3d664d43ed38b3043451), uint256(0x20ecd8355dd94b55d846ff521e75b492c465b302b53dfadfc4e5490138094404));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x275f2ad7841f8d738a5409487a1236b85762f6605f133ff6acff224e990cf4fc), uint256(0x2f203d5342b5f4dd9b36e6cb9fedd527ebf0c41a879e06fd910666760464243d));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x102b46f4869da5b31766bf523e88047e62e8dd8b86c538a0b13699edebb955b7), uint256(0x18e00f78734ec1e8bab4266526a2c71f2cc82120409b90c9853b53a6295dbaf2));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1f130df37b242802758655e1daad3c4046c7462d99a93dfc595c0dd580d66b01), uint256(0x2ccd39c09cd618ece370d946a5b078b59cc0042e5e8ba2383fdb4bb91fac68ce));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2e4eee775168e209a802efb5ab07f12cc310118d39503a71fd0434f21258b2c3), uint256(0x0db6b63cd88f460174b8e092a76b8ccfa36aeb318d7640187db3297a9e2fa8bb));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x01eaa8928c3953f9c9aebea91453884d5efb5105d0c56c350d91216b596088ef), uint256(0x2ab0916a2de7a19e6ba50e2426d62d0d913e511cc51a912f8a39d1b714fc3dd1));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x134c1e0210114eb9cb54a90c7ee1a192e65f6e45b6ef544caf2da057ce35b7c1), uint256(0x14cda78dd0276a92b4b4842e0ce43dd228dd2debbec42d20ddd18f7ba2321f9f));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x2667c28ca4330ef4fb0a065ec4ed8b431081207dc2f151de066c81af4f8c2a74), uint256(0x12c66983981dfd7e9517bdd948ad99b2e22d5137eedcb1e5b4fd1ca8b8c4522e));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x08c034a9156a2af5d031057489d79afad49d657d5f893c718d747860601955df), uint256(0x00750ff42305963423bbe2403d059e421dc5ace198d647cf29956e4c2770e002));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x232ee76b3277e724f97ff429f9db00a772ca9bea6367b1d0cdd2f1c28a9e39cf), uint256(0x211a2aa960360fdadcd7efda98ba1af86e616267e433ea2dc432e2fc95ec09e8));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x17c7892a9860b279921cf85776bc56660d47e20eba95f712ad455cf3ab232a64), uint256(0x076419f5e86bf63c6fc3d5dc8b1a47c2b4bfe25d786c336c559f83c38a97b8bc));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x19430f2ef329711582135860098706bf16d07510eceb40f8e8114710dd73dd2a), uint256(0x2c15d5cb322c75bb3d9599a198b302b6378272a8fe6645f529c7cc9927ebfb61));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2e4178f4d9ee6bd128a973d51ea32d157aa5aef21e6183f16b34ddf0a935ee70), uint256(0x0db14d929c59b3cfca9eebb3e722e88b07cb3ad98259e6880ce20b2a8636bca9));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0804c7ea10df323c15abda361f503c970339b79f272e6400d80ed151cbc4d00b), uint256(0x229bfd57ddae24ad0e9620a77ab0540fb69955b6ba3bc6ec6d3cd211e36f48b9));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x20b12cdf8c7a3646308432ee226ff06a852bf5d7adf830daa878be591e8bff31), uint256(0x248ad50ccd2ac7839ea134e9c06906362b1d148b08817187341c78d3bf318881));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x056dfc0862166f35d8186cef16c76c6d9f804d36237f28fad95935ade9cd053d), uint256(0x303cc48db413c6bf31b77f2d680df9d7852395dd00917d61d57d0ab21a75f68a));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x0758e1859f1a7cceb8d0d5fbfd9eced173bf99132af26e8e201a8feee03c51f0), uint256(0x1bea32693424b38a2bbd257b51945b759bca04fdb27407d9959046fe0fd0c91e));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1650e3e7a2b982351ec50e1f6a19f0b52ceff8763a6f2189e5f692dd4ad9c61e), uint256(0x1203e26fd39f425522a218ee107eca81c7509f63108e33ad83f06f7c2262f26a));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x0076c78202600d31eacc223335f1a7adc73c3889719d708452ccba4e105e208b), uint256(0x2fc10d29ac92da7b345a6a5d714565aea423574bb19f99f3a837a0bd60617e6a));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x162832b6ecefe140d68c16ec706f7472368567b85f59b2f780e6fb9c8b34d518), uint256(0x1e14e9a1f34b7430aba6f2e4c9085420f9d0f722ebe6aa9c3588f242bb904c38));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x06c75eaf3adafef4caba63bfecdfef1603f35a07d1910b0b7df5485d75fb2866), uint256(0x20dd42a939c38fb75c30c515c6c801fb7212c7b119eb52aff2cc9d35c743ac3e));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0d540ab6191b0876b38287e42e04e64612faf95b8bbe3a26e84440f94001e9c3), uint256(0x24c6f2cbd7148ea8dc2d47604c7a264e38efdb80d72bbaf3f9f0d26df03f70db));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x29d634a6c1de55bf8a523d2a93b721b806238e4f41d1c9c8e89ac3ad23d9327f), uint256(0x1229a65c085d7e5100de4e8e106a4f70db6d19b696d273a45bf45ac34f3d0fd8));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2443780eb79863f2a34208a356b09b18f42aea654263b32a23e6f20aa891bc73), uint256(0x1ab5d492466415843b6295742adf541e87452ace66498cc6d5e5b3c8ee836a23));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0866a29c8d536ffa7d841a2c7b949798e33faed710575a4db851e673602b772c), uint256(0x16c077203beca775925700dd46d0f55007e8db0498f429c60c5399d84c24faac));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0a1ce08c3a029fcc9839435fd225ddfed61145c6ea9c0b6de303c61c6e9cadd2), uint256(0x0b33db98a37f98e87922422bdfc020d829c6071a37807e8981123e463bc75f84));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2f55ef35cdd9ebfd5ba5ca124229518af12838df57647d5f86e4f3f29548c624), uint256(0x1e7baeb62305c0928c5ab368e4e31b17fe3ade5ae054e4bf4aba3a3d139b40f1));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x277fbba8478aa295767db1cc39d0226542308c2a8689b48e3fd732698a6a5d18), uint256(0x2f0042813042e060654d5babb52ce5f0ec03e6be7c6277b65df6fcf2ec156d0d));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x2d5333caa2fc7f28adad3de0d18e685cf10408b0de2f730dc2a7aedbb8356bfa), uint256(0x0ea683a1404c2703a2471db1dda39c0b8b41b0fca958d11f4fa6ff66817ceb07));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1da2783f6d8faf9b6dd2572b079649560ea70d4577c2917e14f535954336928d), uint256(0x0854460757c28fc2e33bb85c55d7fbcb90be6495a89218ea28ca494bd45a2d6a));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x14214c89d248a00e154e945dee5a736fc7cfc3c9267abb5fb17ec69a5cec6740), uint256(0x2cfefdad47842d8ee5799a803a18dce703863644be0f5e1132f95fb908d9ce19));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x03a3828e911764550667d35e406ac2278acaeab20b31833755dbfab77e0f427d), uint256(0x0875129262951dad29a1ba4529cffceabec282223ca600a63c6cb961e8e08fe5));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x002b238446e79cda843eec274ddb8203173edd7cb3fbd284cad4e2bd422d418f), uint256(0x2a79943474e0141e420029c219b25176bfc0bb2f7fb31a68a635bc3266fdaa97));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x192d98ce76f486d65170bbfbeaf403ff77784a6ee73afccdfaa9404e65e8f75f), uint256(0x1ea0bc82fc0444c2266282710d2513ea69b86a6113f4bef16da0a0d2141b7a74));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2e2147369ab8522538702b35f7d43dde2c41ade28098332dd8639afc3f19513b), uint256(0x1120b913f50503156d342b2064ee502407dfaf7f3cba704a155e1d4d4ed2d273));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2990ec91f852a63597b3482be6cefe8bb6ad991ee6aa1c45166a14a56013f1c5), uint256(0x16faf2e96276c9802525291da87310f8cf5018053a48c95cf4252270f9ceb2bf));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x254e7a581e6c254f6a798df624db2a81397a2fa7b99a6b552b078a5fca8e2128), uint256(0x09133ac20da1c2367d681ff4d9ed56ce142a3b72e90420d6ed27ac7d2d0add49));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x221079f4a59b41f20d2fbfe9acff9fcb2060d5496452de57fe4e3aa298663a0c), uint256(0x067d25a0bc6207547ed3510dcebc185b464f800705773d735830e204d3e328cf));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x0b53870f50abed1b12c07f0338c9a86c5e24152dd25d7637626515e9b70b806a), uint256(0x2477de30e5f5685b695dad5da3fa4fe69b5ef52592227280d6b9952d57a843f6));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0b1b72ea27dc2ccea8eef769e00772ee8b61a33b27647ba4dd093e209b9160b5), uint256(0x15f56115ec62801d00b8090e7bc0472fc9427c4b9354fe877c9150afb2517ac7));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1f9477b786dd58f720894d811d41c353c5deb76d12d9312a42ff90d89d93f15f), uint256(0x03eff3ed44875fc98bda04bf44ade2fd076ec63d975335975aa74aa2edd72fe7));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x12bc03b7476f248a35b191cabcc6105e8c7399bb5f5e221eaef8f4b66195bb89), uint256(0x204a51af882d90da004f3ba9f5cde400a1b450122ef442129b5c9ecddd21c981));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x020d81df5a34250b69e44b81f04631fbd829e6407f28c3e87fe3d170117b243f), uint256(0x11714bfc393feade02fc43fd6bcbdb788c76f9b9daca61e76ee0cec15b06d080));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x17f4bb69c54cc38bd193e33bbbdf9b9e36e50213678663986bf263fd16ded66c), uint256(0x1c8c33f044d02d95a55fec83292e060ded51290771812614fd17df4000024a51));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x04870065c9aeeac3cdd3c3a8cb8629ec619714f1c215862b692a71a51eb4548d), uint256(0x020173dbcdaf712cb16468f6b03e5fd3a286c3d1de7cd8379534d240fa1b59ce));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x085ae9ecb7fad6e74c11022b131569d261d37c5aff5ac7840922d4e4ea1e7f44), uint256(0x105887fac19c0d76c9c56d29bd7b1f205a51c37611cc39aae7483dafaeee3b40));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x083da79200687a1819b8cdd2208b7c441ce1a7d5f22d544610d9d6fed06d17bc), uint256(0x0f5d234947b2d08fcbf0a8e38d1db2911cc727d46f078c03479aecd4733402af));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x207ee68e9dd75a0030533c4b7d050d2522e3c5279b5c3d4d71e436cdb5d72ebf), uint256(0x14e42229f65e4130609a3db7e6faf98f46a412a2d5f8ff483a3ed1a0ff4ed70d));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x0d5fb106bac67deac48259f2e2e6160acb254744311a26553c4220502e68e1a8), uint256(0x1bb7c94ffe28091bfcb37cee557e043a28f3811c171397b93de0c8924d58a932));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x17ce3996e9b31ef655047172db41d7ba3035b77231fec92212fe04a81251d488), uint256(0x29f2f5e51d6201800d0ec364f380175d5b33a485ce4d4988bb14cb220f67d8fb));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x2b5ba2213bedca1f3faba860cb16e60bb29bf31c874e8a5a9955b59a708892d4), uint256(0x2bde07a40eb9eb17fece2418d5ba684f1b9e7f2557cacdc0ad6654e56f6ff566));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x03df3f42e2d8f3a5ebd4151b563de2afa8f6951ddbdf852ec64fa5967c130895), uint256(0x286eeedee9d76ece590449091e2a38b7a5198a65bea9a0421dc7d5c13f9d8a89));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x28ef07126b5fd8625b4f35f335d2f16b4e232f142dffe071c0e29dd0ef5f9bbe), uint256(0x0465e068bb20051fc9c29c886822512a57ef3c543d2dcbb84e8114526832e5ca));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x0df87c1b0b05451b80a4a9167ff6b7e18e88c05422b5dad2b439e9e209ca61e6), uint256(0x08fd77c30f572d0bbe058520c80fdcb00c5992566a2eb7cd9e6cf2ffb5b5e9a0));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x157ac47a3c928a21415683bd4732216c7fcaab09bdaf1088fae80678ced3f620), uint256(0x1c1d8f890b26c74cfbdef6df185338ef9398cc9b99e4defcf0cb2df42e41e895));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0a7930e1fb0b57722a1a628e4be3a013f0226adf190b12760decb0a1b8f941a4), uint256(0x011ed3f9d6b4ab06c6ae31646d313e152690ddccb7fc461b8eee076a36e8b668));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x0cf5515c47d060385200b2d5cbc80a1cc36576b20a03e4c52496f4d58225e2f1), uint256(0x28985672f5dd2943480bb52aacef452a2e5cce58f7cf471c51d59baae5747e63));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x2bcdf25be8344f3f9b982475f9efac9525e20829d8688fabed2335f246af8e3c), uint256(0x290c7c2e17c0b5b25e18d8159f9bac7b0ccb71b2ccc83c6583b65d0e03ecd0f0));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0c0992de1029d728fb78e7e5e409cd791f9d033f7d65e0899abd07e05c0857b5), uint256(0x15723b524ff1d2cb18fa7ef6402d0bbf5a83e6edb3c9ddbfabda0991dd6f68ab));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x156d0254cb0163d27295c3c496bc081319a227d96fe4765cdc484b843cc20bcb), uint256(0x12745c7ee42fba432d9dabc92ef52231c85850cbac253cbd6e134dfb570a8180));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x10d4e0a4e0b5e18c9404c3b42620701e79853288c32aadcfc332aec6534e051a), uint256(0x2cbffc9e6053ec4c42937373f6247c23c1c681cbac33de919a0b6aed9245edb0));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2c9bedd928c5b2c3b27b4fd48b9a7a98d236aadde99c25d515a3b25990eb29a1), uint256(0x0c8c141e6498da8ca6d9d2ddbcaf14d0476cd5332c42f99826d6984e56744582));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x0f567cfcd67a8de8ce2ecc801bc33094c618fbe42df12817bf11b34812d1e560), uint256(0x237527dcc579bb5720c44a1402be81f2cbdc846f7513ce8f6ec95a40bf42d407));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2d8d49c31e3ae177b9cd1f8abc5c27c9d29d99aa3cc68ba3b076a8f819a09bdc), uint256(0x2c7ec6576d25e478c0fa0be4b5e59d74041b6703ebc1f23a9176cf6c0a0cbcaf));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2928b648c83db64881a2e93715893a07d3613f374b0c1c0bc8c6fbcefd0c69cf), uint256(0x23ba492358cb8042fbb420d9a4b38564bee5a454ad200d3e0572907dc8115775));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x1879fb188625c2585f131ff17db2688b21f6500e123bfa25761ec586895d202b), uint256(0x093212baaa94f493c100bf7f13da6b992de2c4f6c3f3e88ef6625870004cf6a4));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x129c9d74fe057a6c609a330bbced06fd556f3214be1e50addff6ca5961dfb897), uint256(0x124e8180479ff9c5f1a56f6aa0d80582ebf7f763a332aaf8e5e92f50526fe24d));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x15cd0b2de910988a360393aff36995d610c148e2709690f0f0f775c51b6859a7), uint256(0x0bf0b3f5e7c53a9a9ac5f0908a71d3f08b73df4e2cce04bf05ecdfa718277d51));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x188dae80c10f28c1a4ebea3b3ae8859e91117b8120bd3a10c5b8664039dfc481), uint256(0x243b941f7413f2cd2ebace3787bbad65d2114cbdef435f5b0feb8a01bce40ac7));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x18ffab8cad5ab29e2d827fb35ca757df6c377f0a4f38ce8aea0b45d9a38ac9e1), uint256(0x15ff995171dc38f04b4e39ebc30df0dcb25a0f39ea1351387da23d308acd19e0));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x14d4601505567b325bb57b47c010970523c4d5a857748f585ca2bf9717e29d29), uint256(0x1b2f4dcca5b4dbd90b1503bf6f94c1a675c71aa0b3ccddd463046640efe09895));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x120384f802167cce5494134f120371d664bb19b16c569ad2d9b03d0b68f623a9), uint256(0x2434860078abfffaf0fbaaeb5a04d670087595ab9d18b6c47499cf67d40291fb));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x2e0f6a142daf82bc120ba8746d2a5b93512d7afa0b619528e3c525f85cd12d55), uint256(0x1a7abbe51dd4ecdd2b9c8a9d2e772da9d77ab2385516871e1a8e819263c26d3a));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x09e6ca61f33bfb5ca9d892b91d760ddbd5f735a561591153c3117d2ea997fa21), uint256(0x0215193f673fa4050434f8d94de5d913366b955ae6e713b9df13b2f36c03d803));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2b0d56052af4ecdac4993ad549832a3c8976ba764a81bdb9c0cb6fceef768b9b), uint256(0x205fa3c23bd2daa28b00909d741316ccf1d63b415c06d153c8d465423f659785));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x2021f91f94748683a7338732dfea9204ae78cc5e73477af46c3077b0a3f1da46), uint256(0x2378a045d06a94ba6597bf366590b2630b3b86df48a2311fdcca3b90b6996e55));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x2b58dfb3699a1b58066e71f79c660accee72d98acccaa72181e7124a628d075b), uint256(0x006b0e1e610025fb1d076b51fefb55d1b89077c19cc405f3590651e373162d6d));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x029009743a230a7aeff6e292ded63fea2823e6694b50cc9f3b16919b1d26d488), uint256(0x0e62820b890c2cd94c154c7acfd35226857a9bd4c6b0c8362a4e4edd18ac3a2a));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x17fc7c72f57c77e8a0803c67a6c8817438def71c81bd18a63c86e27c499f01f4), uint256(0x086d38bca9e8fe3dc088a15b890ea9fd4e19841eeeed3c5e5891caf07fdf7b58));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x0ff009d7de7fc975a9826d75c065460d9a6b5c27d4974b81c36c9f900243d84b), uint256(0x061f4c316a1c59b45ad971670674c0491e010315a22d57403ee524e8e7dc30a9));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x206712629d66f8467dc43cdf47f3e9724e26d6fc5bb5925c83227a8664bdca15), uint256(0x0ca1c15f0fbb280ecd2b9fc0f21f9ad3d87dc9498cae5ce0fb6c9df704b74e2f));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x2d9de0f8c06051d93d949eb66b4b1db577cfdf250c1f97c33caed10f4675f8b6), uint256(0x2abdd3fe8b9e02440fb8916eeeb9576d67556f13a9cec59a1053027e1463a93d));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x1000a0fddd6ecc8763e6615e5cdd4845254863b40503b93b9deba5412bb04676), uint256(0x0878ebab4832a38901140a7cee8a1cf4b2dba8d151fffdc30e673b0ad9a6708f));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x29b2ca8c384b647acc3434c313e269dc217471a0d05065d51b763a7056f34580), uint256(0x2d1d9eb54392f8f567e4da3642e9a27bf0401c10f1a70fce4efa59b2e40f6101));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x05dfe153456ba9a7bf8c651de2ab934b6a1dc69907bd3c680ef690392396adee), uint256(0x0603be3374ec55168ea194eb608036d1ca34e8fcaf993bad607b9cfa29c275f8));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x29c20ea99f717996896cf697c2a181aeec3a64624e1b0bf1fd16736a533a74a6), uint256(0x1c285bfe894fa66d37ee8468be9a8b30700e3104c690cf437d46180231e2e948));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x02674ab4877b938a35f546caf1512b36c3101af692598666d03dacd8a4b33473), uint256(0x14e93dde833042a4a8e954e80b0755e25a432733b0c10e5de1eb35d31942471f));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x2c17775134bc5224c263c8749d0a8d38c867aa05a4b50ecf382d90186eeba6d3), uint256(0x09338a1351e7a7d19b2841e748e1b296bb0fab2519e0f446422733321cb8ea9b));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x0a326fc820704d650781d7e7af0c32fda1919f2feff8afe4304baa0c24dad87f), uint256(0x236c010bbe07346e945bcce1aeae85275cd5b6351ee5465a0bc27ad6990da984));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x0de42c4e04ef8705063dac5bc2ab602428456d349b87f318f6634c66140aadd7), uint256(0x2f561bd152e5b0a34d8f45f7f00f306c655b82fb6dbb6d14a79cb32772e301fc));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x2138ab3f91eae7f14a25a74f890f55cd6e117ebdabf74293defe8cd0ce7c48a7), uint256(0x03e4b95ebf3a3a8585feaf157c719be72a05238f16940a2b40e381859e63f974));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x0801539174b8dbd8ffc98704d8d95ccdaaeca5ab4a9f9f0c410afd71f9be34d7), uint256(0x2fb8ba58dbe8a28de2fa5fe2ab6d61d6d55612c815f163b57bb195a54bf0dbfd));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x20fbba1bc972995287247815bc077bc0bb2fa512cea91bdc22629408481a24fc), uint256(0x0c6e41848567dda50d0e71353a0ea1839b47d2f3b0cb514ea166d806dd923eb6));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x0207acde76b9b2841852cd27ab418c21593b9eea0dd1352b5edead3a8aaee63b), uint256(0x1d9b9ca2f16f823b287a1dc53d03012567c7a1e2d514860f4bd529db76acf4b1));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x0a87e50d34e3c062a1b751b73a89a4580fe404e1bc9558dadebf5ce1a0e9bf1d), uint256(0x1cbd3fd89ed8e5556821986f18d4da04421e7fb823cb6d02279a3fb68f851535));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x2c162d4d467c9dd49246096c68ba8afad5b17b4aff70435495c1967362ee4f20), uint256(0x02b1109fc50210202fd923f01811c566c3d1eeed6eea85bcaf514ed543d9099b));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x043555ffad7da1aa2eed726df90e58effe973a34cf01647b116632146a47bdb5), uint256(0x122f819bd01ac16b13faaf1ed7edfd96363d85423e51d405943a06ffe4e75ba9));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x1aebcf16593b0754f73952a11c2da8a08c1c3f499060f539e9a55007ef5a92e5), uint256(0x06c83666057b870ce44901aa25457f47acc9bd573f5463fca257b2661c277b42));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x18708db2cbbaea522ee97681d74ad5c5ce563a6fea3889224822363f154ea1bf), uint256(0x23ba69574f5a97f611f6a2076b9c80b8e6981bfbf23c1757bcf000229479dc5c));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x0b095ec8c6cd002a82ce37f2697f04f4292b2c57d82b40661f9fc5cd2015511e), uint256(0x16ae7d9c8b8af45b79bddf8afc4cb00fa076949a31baae7772a175f43db741d8));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x29155433760bb9b096e329dde3f39652d0787e939d98b12139717704a20a839e), uint256(0x0efed11e4b4da041a128fdee77b5e573c43acc059eaafa279f3d7db623922877));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x19421c5acdab613ea09ce4dc31b72b50a4fdddba7977dc7a41a20b7ac54e4dd1), uint256(0x21ec83077f487c62b40b0eaa586ab0af867755dbeb5f49b4818f26263e36502f));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x29472d0b7efe9344d581266e9e4bee105782142bf0ce67729c367f2aa314e64a), uint256(0x1edeff80872872c0111a0cb2c176acdae67ec25405ecb9ce435cd848cae49b8f));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1600eb67130ad3022b67279aa9da645e748f0fc15ec3454a99be45c3681ec405), uint256(0x1d6a1f9550ff126786cc0195fe9345d53e7d9c416e8c3829727b3356937c5de5));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x28d075c438a54438da336f9815f2a7a577875a2fc24ce8a6a69a2b8ee2caf5f3), uint256(0x23272374ae27453ca045696a1bc0ad98473820f6ccf7ce03bab62e4c04969a47));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x013e63b582ba95aacee26b780480c1ae5acc01121a1d269293cfdd0ba67bce9e), uint256(0x21cd27f45b30565fcbd607953716ce9c7ed840bbb905a509d7222a829b7cda05));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x2be0968319434f9f16712e082b5186e72af48d9006988efccc1167636fd0b857), uint256(0x1a55a124c1ab79ba7aee50859977a2df8a83a6a86be04f3db4724847759fe28f));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x17aad7c115de3352e12edec38783bc638c1166ed3fbf85b74c9e220f23be2e09), uint256(0x10c1c0d0d71698d0dacaef48580e0e016fe00a7fbda5ee5d417768c63db1711f));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x276c5af93891a648db24dd186a428bf9328ea659b23b9afdf9cca083c7cf3885), uint256(0x098d54d2ea80a9a556f3003dcb75221ed39cbd206ae4002ec0e1b226d302d48e));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x16110f22587a1dea6993cbd2a6951ef33a2cf4380f8f38ff03283e2096f5be7a), uint256(0x129e422508696f1fa6773ad06ea6790177a7aaa433e299d05477fb18b141f6c9));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x28cc73fe6f0b536836a9dca78b3126d7e90343a727a706f0911e3ffa65cd675a), uint256(0x2412955ba6b853f66b77d7b83407fc0435e56544c58b1f83f1606f2bbba3205d));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x301d1667c3ada590ef6c4928dc24aab1a53fb94aebaf70d30ce578c5ea85e82a), uint256(0x2e74e863da5407552632860b3b7f0cd9ce01c8b5db6f21cc53bd45e32f4d336e));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x20980ffdb9b878a896884dc638a0655fd18d5b0d97f97bea28ade8c76fd6dac6), uint256(0x2ded0a36554ba55f68523badd9ed48e270bbc7ea9e3b4f58be5d78a70022f58d));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x2a6ba920e06474b86958c581e2cd2d73f64e7b84fabea46c6ddfb432068cff16), uint256(0x142d39f80da4f1181941f97c1f3852acc0c7637ace1464516d39afd5f02265ce));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x1d4649eeeff8da410e8f8c7dd216a7ef032e3cc1b45fc88122fd6c78ab2a537a), uint256(0x06d057e4bc4d9b8f03aaf3940b1911c8a915fb61a7bb850255ccccf92c74a68d));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x102c2aea50e5f266946ab3e62a2daf0b5fb94618126a6c0a3b4463575ef1e0b9), uint256(0x2981d3bf2e6d8ef2e0f9681fddcb488e354b4bd53a48c8a88782c4828250ddc7));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x01465bc65fe6c5be9462c4197c9e7deae76c363d69c90ecf01d23533ac578bcf), uint256(0x17853c5b52b93f2fba1bc23cb4659d1f2993f0e4fe15716e0428e96c3bb76418));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x0b28c3f149cdf48c6dfb64c4c2c5083b8bb6345bb68f8b6e2871f7e909d23f7d), uint256(0x2a7b56d2918457d6db1213d3367555feeb58d4c46ebbc935c981d1d3d8c55753));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0662972a54403287d494d22c61598324cdb023c04ce2dd84e86a596d57ae177b), uint256(0x11471450b67a54090ea30858a0cea7d85873e2a9e4e03fc4e45b9c16d45f06b9));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x2613e89b186d5b8005448e58bd5888f441b18bee8ecbb346d76614900874c5e8), uint256(0x1de77a8b96124ef08382f433692a2cfc9a4f24eabfd5fe5e999994a8afc724d0));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x0e9bcdbf9b0e2ad0c16a0895e6da8c79e24a474cd4cbf1fa113539bfd7548232), uint256(0x1230dbfb5b079ad8d30b406663d87b4fc499c38d21fef2c26bb03095ba9c508c));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x14e4be28a0039b5c0f249ecc9108980c23f5d29c58dc055f8b1815a4274c4a10), uint256(0x133981bc5b5e08436f5d11d356932f8a9945dffc87457ac20364b0367a8dda56));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x2f48af6fb2b3910c74ad7741c79c36f48ae2124cc530e78e0464caf1d619726c), uint256(0x0ed4dc4cef5ea61e4e6909e46c3756ecc3b98dd91cc017c9b3c8fa7f84a42e28));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x103503a291c63226212a067d9dfb8c748a39fd36aa4205175022362a6eddd027), uint256(0x0084bd61899e5a6352c5f6594f2ffaef912cd776e252a9ae07c283b6d03b8f14));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x1624937b3140559af39795feb5b5bd6c0795928461b500e29cbbabafad1b8289), uint256(0x0f796b47d0565e26f4a141409e4db03883e198a3d8873b04cf8cd569a39271b6));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x11f13f8ba42e125145a88d18873cf9f503d8c031a6ea9277edd1117fa9362f5b), uint256(0x0dfcb129f6fb01e8cf1f7d852ae52248d1151f4622be70ef7001139cf31f7308));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x1c573ac9231b74556f05d1c089657ac796ba33769520dc27ebe964765925cd82), uint256(0x2df6d0f087572a490538004147036f9aec3c407887e635052a121eceb458c411));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x26e15806919827d3084bc67353b536032256a727a9361b4dc65eecdcd5f06ec5), uint256(0x2ada3fb6e4b0e58f8bbb6e3012c4db5a5e4b13b34503e757f96a38f24609727c));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x2b091559dd9177088e5262a483bffd79783524b6bdd1ee5a1391f4cba378d6e2), uint256(0x193a226049362a852afe794b43b75c57e7aa28e38c32e99452198a864c204021));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x1024385e7acabc4b1a3bd45acaa093ee19a3457ca55985a54806a2616f588bb2), uint256(0x210c7772bb4729d549d3a8291ee25a775d54675b31ddaacf187b5508aca8a707));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x0733795fc8ff096ffb236a3092501675977c1fd7fc44120447b679608b17013c), uint256(0x0e0f7e3bbd31caa542a371129beae0741af380e9ca5b74e1e905bef28967dcab));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x2537369c3dfd392e66335fd00e0dcd245aa6d03aba969398b70bb6abfe347c38), uint256(0x1ac13d06d68f7c86c6c31b349af7f6063e1485bec8798fe5335e0bea552b8efc));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x203e7f53233af593e80acabeef04e4dcec66c59c81b7597954627cffbadf5589), uint256(0x1f675c5334a0d05bac0dc1f1cd19ebbe353e85bd27a0d9c7b9def623c20944b0));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x0f75c3415b6272515f51a7fc7d82d8d07f78c5237f97d48af304159f6226a739), uint256(0x2df5b0d8240c0605eafc1c3cc48f624854584195976e0a7581dfa0c20fe2e296));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x0549fa764442dc83739bee1b2ef100ec6a240d976b55f97c22f6585fe78ef1b7), uint256(0x2c5fbde1b94f29be3303375c3fd71d57267ea5dbb02959dd24c11070d8723790));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x2d686272e3d17898188cbeafbec2ca6fe7660a1c5275276facc839b73f8e8a33), uint256(0x211a11c173acec360b6e3c655cd1d5cc192284f0e47008d11613eb7e5f5b77df));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x11eb70e049fd74a6510f51a74e8b92f303323f121cb17dbc9c0df556ed25264d), uint256(0x164e61971cb54377ec4c07a923796408614de0a55392503300cbace5fd47db50));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x0cb0996719a31958ad5bd097683cade65df85788ff4ff9f9507e95ac41207db2), uint256(0x09c594b7777c66a210d675f6b4b2fe3fb63b1f7e2d38a190ff82815798091d22));
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
            Proof memory proof, uint[212] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](212);
        
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
