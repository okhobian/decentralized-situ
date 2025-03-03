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
        vk.alpha = Pairing.G1Point(uint256(0x2f659c11e2ee1c302365d1df5c220cea11d3f0180363b260050265aabc74b830), uint256(0x2397ac60fdf9ea8fb694cb622ae3a2b390d0286e860a23108bddc7fc3b540de1));
        vk.beta = Pairing.G2Point([uint256(0x05af1152e9532659380a72bdc978fa1a0c35463863c539b501cf84a5f166bab4), uint256(0x0df8a7afcf2f625b4f7a898396208f4e5347ebcd568100697825a5a097958660)], [uint256(0x0f1f83f5e3723d796a588f11d756fb6a8a09679f96ede3ced61a8068f8e686e2), uint256(0x2520166a125745cebbbd23230db8aa218e82c699d57f58df7fe4b9ff266051a6)]);
        vk.gamma = Pairing.G2Point([uint256(0x0864176c7ab3c5d1e713c846edf95df46c1033475f99de12d4d7eca99886b703), uint256(0x1d4c870d8d6c0ab2c0231ad529f92e24c032256fff998b80593aabd3d7edc1c6)], [uint256(0x27ad4eaf7aa9e7a35c0586a95a874e1f36266cfe98b0cf6bc8bc2ebe8261e2d7), uint256(0x04ddd524c25a169c00d203cb7fe698f5cfcca0a76ed75cc0a856039839a2c8b7)]);
        vk.delta = Pairing.G2Point([uint256(0x11ed3aa01034532b96620d9aa448bed750012b8b8051fb2ebf7914f2dcd9b1e6), uint256(0x127aedc053bc13c02d84c21c31a2306d63afcec65130f8399d2957322b16edcb)], [uint256(0x161795474ac0e162c92dba769b882b871e7781c875bb0a762388b21f248f5b19), uint256(0x087489539cacfb497556d0989feed540ffe5be295da17474580fa172a813fc42)]);
        vk.gamma_abc = new Pairing.G1Point[](214);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0911b47e35d83fc20df65ae8638f481b517a2947388fb52f411c924e505386ad), uint256(0x07e77060e2ef246378b01ae54f987c0ace606593e281bf46a9db65276c755e96));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x157ab539511987f82988f3eac5c6d42d31dd4ce4d67c058c2d1add715eade2d5), uint256(0x0a7fcb69178d0fab727aac2409f6d6e1d6382f54cf0efeceb4e790460367cc4a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x11b3644ac4b7b4f8ffd653ed2a80ae747f1510383dc49707547139c093c8f91d), uint256(0x1d91bffe45a91400b7da8d5c4528468dc878a21a7ad7040417a4c1ddc069c2b5));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1e8bb91a47bddb1c7764237cabad4bce2da2693b616f9c5bdd170115b20ec59e), uint256(0x118f09b73fff51509761936a48d4f60c7515760dfe0d55549ff98bdf6ec3bcb9));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x27d816c3cfb1eb8c2fda70a56816344a27ca7b4ae0e1e8709a9032f7cdb08a42), uint256(0x0a07afd2776379c2f624e357cb3488964a8ae67b2927f696357e286d29cf7869));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x09bfbfe2f9086af0322405e48125a6951829bb46da88c0edffddd6997fff8465), uint256(0x2e1393996a2ddf3defb3e5dd766ae77a82de89f5314d2744257c6c2cea7a4be9));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0df1f51f05cad69257c1669a38769530b8deef3f7e8bc45574d27798c61a3ab7), uint256(0x24ebaeb5cd5ccd6a659851bdfbafa260d25eaea998c536d9875c70116827db68));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x15260266633845e672316455df56aa6c02437501c02d591f256dd4e96697d53f), uint256(0x1126ad1cb8128404934eda98ff90222d5cf1d16f49cab9c431afac8cbee88914));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x00c95372222ad4eebbd097b0851c7fc05ecb8fdb7e67236ba5856569a39d5f57), uint256(0x0c632f43f78a33d408023a748712793e21a721b14d7e93cfa861340668807335));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1627ea12e4f04b293e013244b49c6831965794a8ce290c88f6db508ddd652152), uint256(0x156af133e09e1d4a278e02132ce8da7f9e1435ae3c4ec91feafabc18e8405c2b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2a7f930945f77a40d4a08e1ef7d8a15806cf201b9209bc80b271c35411c91ec6), uint256(0x15c4049cdb3a96cb547682931815356a5f36ca792956ba014e6fd3d70c6b320f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x12d4f5af0e2917517c7e6bde7ff0de02b210f3243c52f3168ceb0613b2d5990d), uint256(0x0240a779d220fe6a69d7fbcbdef1f3bbdf6fd50ee6e7b0f4e4f3cd09ce79ba48));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x28785c6a4d3402b14698726a3c0a40be865bf0e09e03367c8f3fecd8bdd25ec4), uint256(0x2eb61a0f65acedde17c51b5686f912db6da56ac591ad79443527a0e6d2bd9a1f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x081364a7da53b4c917af230a2c2415ec9d364a2bbc0c3f0ae3b915301f73cd7b), uint256(0x10be602fec6548826eac907ccecf20f10356c50cf6390c937b38de5266b11b5c));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x247f4688cebde302d176c23ea3720d6ced4cb119915c24f25df8dfb1ebfc9fc5), uint256(0x2946713630f6d8e99679cb2e5aa4a6cb029b55ad974ef0443c7852572a49d803));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1deba74089c031bf44fc0f8541466499e420f5f3a01950ce6cf25e479801b553), uint256(0x12351b895dcb935bc020635382650cc4e44504d7daaba8415efc50f8689528a5));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x13b4ef8924348c589db2577edecd508be3a19a5ddf256a6a843dad924e8cc2be), uint256(0x0b51fb389cd3e596cce8aa602c5ee19b73d70f67c1c92461a766ffd803ac65ca));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1e697d53621638c40e6d91cb5456e741b6c704565bc471008a336ac168f5dec6), uint256(0x2380ac6d4abb0592a71ee1af024cd402e90231517c658e0800b0d967a10c3f0e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0c1380ceba5c86da4feeef452bf51621ec1b4ad7c1eb121013d7e1c996497d05), uint256(0x1971838d1d48cc813efd971959599c8fb08eac465573bf655bf538b25212c216));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x12e76f36c2b8e8f3b5d9f3fc23d0d729599695836aed81b64322465160b46e9d), uint256(0x15fa3a94bf1da6d382b8f63d5d11442d51f5616d961e9d04a3475ad5e21ec177));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x26235548c7aaf771041724a2bb84278f648ece9ff91a8a9b8aa4cb83f655b73e), uint256(0x2361477cc2db1c5e5e1710de268dadd9926355b6739ca60eab6b74533c5117a7));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2df892733c39adec185dd9d63f2b91f654cc4a106e523158298a37ae7a3e48b7), uint256(0x1f9152c8d44600e1485049f6b3ff573c39d938736ee73d643c5cbb3a648e0d51));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x17232f100f2f551f28a747f042b8a7cc358348cf9a21ed25c28d193df4d86ab1), uint256(0x0954ec7a3ddf519f357213c98183421965566057be64fbf35ba32fe42f5e8eca));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x07a6f283b62e09a8aae12906b028c47753e6cf5a3a18e7bac67edd3fec7b096f), uint256(0x0db2d7aa13ed7e2ed3cfb17f390224b0e7791980ea368fc0164687ef7d783603));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0b818235393b3c9c58d4103b05e181858b13439d7cfa546b6f02a23da444d13b), uint256(0x24d1315f2a3c4c2a79e3515c1f7516a3f89bfac144f3989d7666d0a402d9fa78));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x066d436b62a3a6b2cc3fd74f86e666cc3c2bf2151f8ccb2c74cfa064e24e858b), uint256(0x10ee2c04e5597f446f55fc7671d2f095fd7e2b433e83d699d6560dcff1da63a2));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0cbc57122658b53ca06f4d3bfd37b9528019b397fec535dd0a90ef46e2ab955a), uint256(0x28cf8a8192b2fa674fe09c7013cb4fb53eb9061859f982217caecb125f81e1aa));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1f6e556d15d5b9007eae98bf3389810fcb7772d179ad123a31c0dbfe631fe394), uint256(0x234cd4a41233c38ea3cd947c3a940b01a5a1799fa10b43b16424bd5929308e21));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0c73d288fef265ae1fdcd38c6a24b8d1e5d064112fb51295f0a7a5ecd2a811c8), uint256(0x0719af4e610cf5fffe64c60bb8a73ac3602f46a952b27799740aad2270fd8b47));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x24480f1af02a1dd2d6f5514686e8d14f1283fc912c78d607b7f1d95abd8eccda), uint256(0x2707e6a810cb3ce173f4e613d14dc893031e1d6486395c445dc29de9cda3c37b));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2b5e9394d51c2e07b635f1460c44954fba6f5f6056587df4e2c67e143d1ec0ad), uint256(0x0ea642d4ee06536cb9d5eabc23a0edb3214c0d86890cfecdff4331e891aee403));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0b8590534926c34730deba8e2c28009cf673e98bf8236d466e06f97057809519), uint256(0x1a8908a6eef5df9509f196aff61a710aeac5fe617e29382def119ff1bf50ecd6));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2f381c456f0ab0a6e63f189d730f88a733118f95c53c4190949651b185d43e59), uint256(0x07367629bf59b58fa979a001966925bb50cb256415ff49c798fe1d5d6c150356));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2c4232b15b05c70be854f35928ec3380504dcbd8975aac4819a012a075fbadb7), uint256(0x0cd86060218fbc6e4c4ec8611a553f41b11c9dd39fba7f261527b58121e50b64));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1fd7b1702896e828cf98430467fe8d559ef6f2f1a227bfcf99f35c1d2a746c3d), uint256(0x3039d05ab166bb56cc83cbf7355f1f52598257a96be27e323c1a058d3b9b35d1));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1cd3afb56caa4c11df49a13c008a6163954c016aec0a1c6d0a11d31bcd4d8ea6), uint256(0x0241a10863fef8a86cfcd3e5ecedce4b3f2e83af42f296bff8184a6e6a70456a));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1236098e4f0b41c25f08ff28589b9cd9c23d142bd6ee73b53569bf1a42dfea1e), uint256(0x0b03c5216f20d1df03d0bd7bf5087da43cc327ea246f87f94dc10600861ba3e4));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1edbda4572a45dd6bf8f612e39bef9a5c56943cbd4435a746b568dae37a4da67), uint256(0x1d4ce8ff29983415214568c1bad9d6c689630d9c97f125c06412eccdd2b8cabc));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x18ef5562b0e8378822d8471fade5728e274e3d3b4874d5aa3b7304aaac2e4708), uint256(0x2a6766bac682c9001fe6e0e248f6cabd84afde46e3a83f1d94a4c8f748698a79));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x03b0b8f8d6b6db814c80db8a4b89fcc1bb804c47fa71a81f59d48858fc23a6fb), uint256(0x117fcfa61ec3a6b4c1d3f5a4108fdd7f078730145a3fc2db921488ed53550cbd));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1d5188f183e12b4a1a752f5bb0e800be5f8e2477907ea12584b636467c8dd06a), uint256(0x11abf0cddd88f622db591b9f6bd87066d9f7bdce9b7d8570dc34859ec70f95ce));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x16cb5737b8410420235a5304c011fe8d2aefe569af7dceb11f482b3e01677309), uint256(0x04169df3b514eff1b61d2ba0bac45ecbd758fc4e5511eb914bbd354593b85f5a));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x23699e935ed7053a84d290b1c8d2e837dd236ad85d372d9d106c528eb6f0b71f), uint256(0x2882c0cbc4606d50e803c85ea97603661a6c8613af7b1604d39a14d24ece700b));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1b4c3ae9fe18219b30200c7dddadd426d6ac0f0de4257e1f864e8f33de58acc6), uint256(0x224d82ae8354743f46bad9385e0fa498ab63791e0a57ca3cba85d5498d4fd67d));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0af992bca1312ba35c71b70e79a85cc2ada2f4d53da89dc8e1b0145a37668b54), uint256(0x2ceb37767a9c20ca8224a0a1edbcf6f9d4834a453279a3c9ddb5bbb0bf6676b0));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x17981be52ba85c6fd269fc7b821b074ea99e13cc5fadc852cc19f95e1691a775), uint256(0x0b06365bff2136c15e69875760b5d97c22d89b0ad6da49d68b19df34f73b7900));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2c34bc06e30bdd4b77eb5f5479632106b7ce52409c47532edc0f2498bd9a3159), uint256(0x00d9e05d3f016fdf354d130a5950902f777689aaa01dd7bdd6d54e3725d473e3));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1c705d1e09a99f06b607095a907ca06a96b6307c52166325391a5c27f3f5101d), uint256(0x070ed29eb39cdf7ed37d2944e18f54802e0372a7560755977c53e7c0cd6427e3));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1a3401cf6792edd9fb27097b9976419a4a069ea7d2ee874f4fce172935270a9f), uint256(0x1bee92ea93674bf6313051c7b16822b74a7ac18945061da9a9732aedbe480cca));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x16413e5724a43a7d0bec7b92541f30c779ec35362734a0df9b401dddbc49bb75), uint256(0x1949f4bef0e4d59599493e5ae77b14f766f88eae53c6a8b11544523a6753541e));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x0a67293dd9ba44237a25dc0e1e0ccd538ae4131dff6491b6b592f3d7d3b8cf63), uint256(0x19d82aba6e8c653ded42274cf7fcb8904c408b16a1fb1360895a7a20616dd036));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0172315cd2aba5fbc31a35e89c08a2a8df6873bb69a5905f34e665d4f6c560f5), uint256(0x09fb9102fac4b69013f2c7b921ab8857899ab2aa15e553097ef0155267816403));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x104cf0bfd780e126bd34f5caa26d5146c88af73391252f6ae63739daab6d365a), uint256(0x11b45d00ab667ad469840145c43d4333c97e8b8eb9880d3b48cda62d26725c06));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1efb991822f3987b8349f00892007a05d6d35ff7c61153b3e23f768b333509fc), uint256(0x052bec14347bddc3d46c3644d1386a4ea6ca0366211364beb91feb53c9eb80b0));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x17c5d569600bcc123321a889a8d6003e8ef82fa1480e13e82cd25f76566fd6c8), uint256(0x02bb8f64de58c93021761c030420ad4bedbf5468f67c85f30e9b71b4bb949afa));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x276194373e22af1d7a406220cdc906d4d43f3faa44dc62f696dec952b93aa3c2), uint256(0x1c233638640809b35d69aef163e5c97a1cae63cede5e21b7340bf6b4a50fa59c));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x26bd105fa4d41c12b5a6bcfcac1d530877961dec797588fc262d1495183d7cca), uint256(0x2d34156f6a361421184187f39fa985aab7be5672ee03ab7a84af37fc4f25cfd4));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x15edb5f74aa1c22ee886674290e1f805bce9a1e117f118f83f5ae15c0b1d56b9), uint256(0x0e688f394f85d5c0b4f71f4def315c63bde29a206ac05f472a4ad9b76fc6216f));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2c086e02a514ae2a7fe0d5396835468e1d270dbc92d6df3aca160e44032901d5), uint256(0x11133f00d70abdb22da8a01cce0b725be5336cd5d1e1384868aa81aed4e0dbd5));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2a2c9f67559dbe397f31132b8c62120bf2857b37c42478494f2d032969b04c23), uint256(0x2cc414f307de3aef39164c791c3abc06bc144ee1d33fd79a2134e5e5fecab0e5));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2af97bcaca63d2829ac1b704b19b6599cff13d56eba883e14bc54a58a2803b59), uint256(0x0f2740b7ea02c900eff0dcfde91f10fc294736fb2c71798e4f046a9d3c883c21));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x26eb88f509b64edfc8d2b7312b81c604fe8c507323256fe5d9c85f759a9c26c6), uint256(0x14deaf36bdb1784877161ad8cb58607b401500fe735e41891fab125a0c8bb5e9));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x14e0bad0bf8e0d0de5d11cc1bc8f40825328f7f8bc9c45b47659814d6b5c2096), uint256(0x1607cdad23d6617b6b6824f459a5c71ecebe689d03e6df374deb8d7cf18f6885));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1e53e3787d929e894e0e006b6e334cfc3f7e8ff4f91bcbaf72cb1647b22cf33c), uint256(0x1e704ab99dcf603844605f4b92d43af762a0fc7e3f7b0ab7693067911606bc26));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2dacb8f3c6b4fcf7eeb4ad34be93ffa9f165e2537bb8927e34e0d90b750e4660), uint256(0x140683ca413e19b52b304775734c422280b994827528c876195c575e2e070cca));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2613637689aa24297b1b69f609ba1acf90a5876249c8c47916428c465efebdeb), uint256(0x1c1a9ddba139661f9d51d39708551670e7f9dcc4e71efe0950a991e7aeb87ee7));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1e2cbd252ab641384bc886d72fc6c1903d07b54861687ba674d7e1e66b1dc2e9), uint256(0x122120232ea2d98683d9b023498f95bfbb65db7081b86c15f7947cb293a6ee83));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x20394ec98effdb7ae01a9d81250c9fb836b34bf02c81c88d7992fa2cf01e5790), uint256(0x01b94f64ec7e431adadfad380635fb1ff81bbabe3d30435db89ce669971f24e2));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2fe95add4ac25c98fcc67800d6e9a5bd739a60cb35ecff2472642caea9e9d7ca), uint256(0x010c3d86f889bc87556601b2c2d2ed0e29853dd76f9d42a998d9317439dd2580));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x2080e1b9ddb41e2baa173a0dc9efbb7dfd8960e83b0af921ee696379b4a7f0a7), uint256(0x01890cb8255401a058fc9f423a02598ecefc76f7481d93aba6b69fc41de815f0));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1443fa1a88a33874bacbdad3fa09d5e269cdb1dedb9c9e112413cf3c29b49808), uint256(0x2f30c6d49db78bb3292bd76ae57ceaec4cec7d6ed4ad988465ea857b4163d98e));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2a21fc2286cfb2b2447220e0fe04c565abad6fa2808a606a5d2967f9ffa76a09), uint256(0x26ea114e7a36d523e4968920cee1dd7ad28e0510790ebca3f962b02c73f5aa45));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1f5ceec02d118047bb753b7ed4662d75f8d52a75f9c59eb439a5005ffa55f9da), uint256(0x15ecce0781c59e1315d7cbeac8b689b1c4e7d34a099b4504857ba5be34e0d7cd));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x119b3edcd4addab5e04dbe4d2ae67827073f169ce9e62010534d80f2e2fcec7b), uint256(0x10c8932d1de701fdc5abfa475e7d251c77649b0302350f33e37d56951e738ee1));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x28f4f2a2b054c231565a81fbc01c8a61f8a07d0dde5470bbe20e733f3931c192), uint256(0x000c2df4954abfc819ce1c0ca13ea38fba2f52ea7eb12b0a99fb431afad822c1));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x065550591b9f280c69d6719ffe5a1c5d61a68d8a3f5b0d8dd9c5fc8125c18105), uint256(0x0d81578207cff535e7e993e046c7e6ffb7fcd0462d54b2b4a293629b445e401e));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x06a1489ce612a5fbe38726e41da3f8b2da796bcdd0068e631dba38b78e7a64bb), uint256(0x0072d8713add01bcba80c9e8858f1b17250a932e3bd59f82158bd006220d5aef));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2d9fb4b42725129ec5c027a1718b597a4416c890e594974f71cde71cffcabdf1), uint256(0x087fb15c8ab5bbeee167f58f532557853204e0a278df46a599fb4ccbd64f1f03));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x142ba0e09237aa445e3b9c013d8b3be1732ca24a0b88d8c2d05e48fe6deaa070), uint256(0x1043acf75b6c0639b7e13f16bca2f8e1c47b7ca48584f8e6fc2bc27d422a1443));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2a279d70318c69da44f8594b41d4b521acb1ea3f6a169661b37ad5c8031ae54e), uint256(0x2a95692db57025fa100b542cfe6610e4b5f9936c9df84db810b6b96085e52a80));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x17424ecaced1bf2947bf2af2a940072183dad8faa70d67420199479cccf62a67), uint256(0x0f70de6372efb3d7e26ffd7a5a7a0d8680578a54b942e97fb69a7c56ceace4de));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2821d263dfe4232c2226c76455a0ec302abe8d306e4e0dee88ede23c370d23ff), uint256(0x00017e5bc4272e7504f2a842bddcc59a77f9cf3b2c2d6dccab59f00ba60db8e5));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x28aca70c20f5dbf923b8064133b72fdca0b62f541f04f9d5ab17675c24357ff7), uint256(0x159f51588106ab371f13070f652b7b024ed4548bfeffb7e8c59c8b9cbf2d383b));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x084d5600b65bc9ae7edde0f941cc49304709469087b3328b89d9457739204a49), uint256(0x02b674cf078e4d16c4b493f23fbc9fd3c2dda366ff5d3c64e0390166df2e9f23));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x14fdbb8830bc95d28774b140533381c5f68cb5f2d7db7273b37874a27d317d53), uint256(0x16069a266e67a007f8f996973eeb4110e22e71e46f071c9a8c1839535943f1a3));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x26b11ee2427f222a89d4a4f18da547319830e9cc0124f9757517bedd7c4c43d9), uint256(0x1f9c93b65e9d8ec27de0706c3f754e62a46067243e48d756f8d2d824ef1b86af));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0fd29c055bd9f55117d3586af7ca8551ded8e8e6eb6b2782de6469a3c8e8d484), uint256(0x1517b789c3edd18f77698fbef62f4f89798bab8f17450c3203a67d02a8751056));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x05a54db30e07d5c7670d89811ddeadd1846515dee2ec019254bdbf547a55fec3), uint256(0x10fcf5b693d88fd01a294cbfcaadb8d1367df84ff8a16da2aca4d08a2b75fddc));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x229c88e508d976766da9c139735a00ea2d2e93bea41a5f9d0e4b36af57ea4f84), uint256(0x022caaa590c94737818dd4f5b09e8792dae5262b879ce12243232bb2e744851d));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x171c3a9ad26ee95a52156b8079b5180c75a324a933d88abdaec1497ab0f393e4), uint256(0x2524e94c55b6723987fa3eb85ce95ac5850a5efce6a121dac5727741155c3c95));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x23be934c8568647bf6f84f8cb681ad831118b3c69e45eee5802c8741540d744d), uint256(0x17598efd097864bd398161e6fe10d71682d47324c0ed7cd05873550a292e231f));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x2d33cbbdde77c273851d5e7e1cbf7b3e043cd2e24cf6c09f804eb893e9debcbb), uint256(0x26ccc8703780aff4b61eb05664419afcd90b677f65e1f55c1e38f1e6dc642d6c));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x2da633a2c2692898a13eeab78bcc0d84d0dc89f640d191ad6d23f21bba220ab8), uint256(0x1c7e42298a999ef68173ac486922322382dea08364a66a0b894d3fa5056776ee));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1274e3d2231a507352bc58727d66e20c1e6f86995b44b7066334a31c1e3cd8d0), uint256(0x0fd3044d3828c6089bb222df503e62c13ceeed6961860a2d2c81c5e3840251a6));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x134a92afff8b9458341b29fcde94495080e39e7ed2e983bbe730e0d4061f1b1c), uint256(0x2835614a949a6de9bc9c58120bfbc14c5ba66dc19c1088a27e10db726e8d3662));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2d0f87eb61776dd99188bbb4ac8e87caa68b2fada042fb4aab873e5a31f624ac), uint256(0x1b681677f469524d8d452a33613fe9360ff3e68ebe1f51d5932316bcaca12e5c));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x2ce0f1e0192c6ced78e3ff6b98a328d8aea0ad235f7f961394e6cb5b2b2f22c4), uint256(0x29128d450766d131cef71225ebd7be5a27ec1bf5090a01da60d28d222263a340));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2b71cbfc23f2fef826bace748b8a1b7c621fe37cbc4d9cd0bc0fc73e715e1a4d), uint256(0x2b010e14184498aa53f718b80c5c75bbdb6928c952a34e9b34b050bea39de1b4));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x290bfb1c7fc11ac6291ef9b456cbf8bf48d8ecf3d0c13531c83363a9ce877d15), uint256(0x28c6b3365a23253e173842a074d6b9364c7c6a1ec96fabe478caeec3bf80fd9e));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0718a57de8d3d564c84e7e484232261edadfad0f1639f340c6a98b7289c5ee8d), uint256(0x2ed15899088a1681b0c8ec7b88c3698f5e71e1b2f66a5c3e3ff34859a4c10f46));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x25ea9da1430c0d98d5e7c98a4eead20026ed7b624cf4887f1edaf8e771e62241), uint256(0x30089fe44d165c98f592b47f0a1df334f0680aecd86aabef09206fa098eb1dbd));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x28795d119f90cfe29a764a2713caab7c9820e72473b99e7c7b0318b78dd97ea4), uint256(0x0b024ec540757b7c32d4dec6f75c4ef25c8facb807a02c7af2b428c0d8c18840));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x10fa8bc4a533e2f293f1dc130d9333067acdeacd9a9b0d7ea7c2bccb746e4967), uint256(0x1ab80842e3b09a3c0240a995007c4dfeb204ce7b79c90ea61edcd0f9702ffbe2));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0505b0521e54c3e7e217445a318def3728c4f744d43d477a7632cf257a72f6b6), uint256(0x17dfe2e4d12068e248ce19ff57a5a9ae6b2597171428f7c8dae47c254d548737));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x29d1f509539f05b435535ec595c914c9416ad2717ff1f8a679bc743774da8beb), uint256(0x14b21a4e6697089b027f53227b3bc0f797b0bc5a163b12716e59352f2f4a3941));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x27ef75b23c09fc132af46edc224f93f08ca59169998f709f96751a787722956a), uint256(0x160317dda82d44a378c32aa9eabcb1624c7c0b0921bb7a81ddca9451bf60f9b1));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1606d0a1d9f937d533c53a6d3482525d72ee922eae977e1c5c55d84d31e90be3), uint256(0x25a62bbe7c855d63d8f125b42d5f967bca43b65ba1ee5f42702a01be0c9cc448));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1a06bdddaff5e281189051fdbe43e69ce4102266de52829840136d5eca930f2d), uint256(0x0e6b98812762127baee5ecae9b4ad20f5f1f5eb4cfb7b390a09114bcdb17b56d));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x18037ba80ee8cd83321a57e4c924ddea96505b2f9c0c8166556ec10667b1c1d9), uint256(0x2c6682d74735fafafd161b4eeae06d9ae00d5366e2959470f595e9b6a602fea1));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x036f9e4c9e4bf8335e942b49e3554b675cc7eb6ecd6e81c07f2dbde4128de76a), uint256(0x08c8d1dc51d2351bee449fd6da2ed61c97ab81667b3e1b198eee54cdd39ad25c));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2964128be4bdda5cba42dac14ad78ef2d2bb8956e07296818b094d910ddb4657), uint256(0x184cd9101306c4cac2a6e3c2d474c1c51f4d4b8904b882fa69bec4413a11ad33));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x1b76eb169f77fabca406f4df35f8ed14c9d9ab32d8a5ea8c255bb1b3e3e2d633), uint256(0x17cb70c415179a3590e69a0500fac4987337b4a6d70db7f20fb800c4a89dafbe));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x17ad20eeb1c4689621381a705e6332db215d48db007029c961e3effb8684daf9), uint256(0x13ccbd87c6b4bdbf3147a8a6785026a8f7129f6d73d14e645d16427fac35c677));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x2ebaef1a2dd011a7b2254dea25a363aadeea9351f3afa71836a80e8c17bc9dec), uint256(0x1912410c81a561f0368c74514dfd87d3955db321639c12a472ba8291d5bf4b43));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0030befab4ac16104d4f376dadfd5754a654804b0a40bdea07892d3713a3c025), uint256(0x21b95f583d6943427220e84ea91c3dc74556170f2cc458144584f00e83d8f08a));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x2ada7233558d8b7283ef2986ce85b7074d2e35691d90a7fc43456d45a686f35f), uint256(0x0c23ff9c7779b44a5e3801ff066b64a07619eca064191d96e2800e6d2e885612));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x196c5d9d9a23a358e12cfd3c8074b60ca2d8495515a38e53397ebef6ecdcd87f), uint256(0x1b979a9068b989bc31e847e346c1aca4efe7db6cbe1cebdff9fda42c03ec2bfe));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2df67b0fc9c3202ded199c22c18fcb22b73830d867ab5cec7b850685d611b9a3), uint256(0x0dfc6c8569d086151a8574b5bc571f025c09e1e119727bb68ef339043052a5d3));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x019a24d7d2cde738ee7ceecc4012841e4ab6280de5d1eaa3d1cfbd8189a26338), uint256(0x0e9e8f8418d4826d2243086228910806b9a020e47bda3d3c7085c247d18e17f5));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x031e80ed3f8b42751aa124af7be0a2dd7b898135e99794e41cc3d462c8e542a3), uint256(0x2359fc2f260f50c52211e6db32518b60b657d3b1bc59cf12aee775a5fb0388c1));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x03b1ca39b9d0a26614fc07abbea59dc8f6fc7533c61536088018b0c27a274a0c), uint256(0x182182e2b3012964e5636c6d39f121f870cb4e224a2257c6cb7ae7a165e752d3));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x021fc1ea93a1f1aa3738d5bb8ee7cb86ea7bf7a0b022273bc24df6f95aef4cd6), uint256(0x0f142185ab73f2648086c8fff462990e0ad30c0dd1c7ca09df8d90f9c5f5e944));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x28d07d41cd4481bac3ef8cdd819d9181711c0571df30401dbd497c37831af538), uint256(0x1b94df668c382729b760d1693a183a4acf75bb2d4561a2ad5ad7d8330692e8d0));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x2258e9fb724ac271e2c159325f8ec80c4fecd6adcf1515be9e439370031c50bc), uint256(0x0b80d41992fb1ae5f9f02a4fe3f91753f508987cacd15027f571d30e490d2035));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x06f1ba726af9e91fcd07ba900243b1f43c2486d4d87e47c4884aea22de560b85), uint256(0x2947114cfb7991293225ab79b9756df063776652901f701fd9fe5509f375e804));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x0ea5de14dbb6240a94d16fe0a882d693eba38fb4acfd06b1c881a0f52434e75f), uint256(0x18e875e5d3ff7fdfefd70cdb5d3b18bce814b84465ce7fe573b38273a2c4019f));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x221a818444e0ca743e7c64dbd1255c9e72c9e484d31e1c4f9109a3ebe49df13c), uint256(0x1e3efb94d5d38f63355e811ce7990e980ed51d994a17d2ec099a3875b4ed6807));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x13e1676c45c05152cb793f60897463be676d9f6ddffdf6518aea73e6a44ec8cc), uint256(0x0343fe106dfc5433b0660b5b5303ce6403c4e53000e0bc549ca410c6fec36045));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2cb0048ea923ad42e4464feb0b4f831cea3c30ac9c0da4ccc0ef8d7ff61c0fac), uint256(0x15ecb6e907d0b598344b72d07a805ca589413a4e0ed6218da187a7ab0ca42a3b));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x13383dceaa7c7d043fd79dd44d413e571f3864d89397f40cf383fd25ce79ec14), uint256(0x0f9b52be04ecb93efd7198926abc6664454cb3d1394a2bcc150eab2bdf9f1328));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0eeef220362eee35077ee026a508d8a55c93f4bfc5e3991f2ea9a11d54b5b9af), uint256(0x261a9e77ada80f5afc5638c006371fb5aa0fad4ab7b8ab81a75a04c1fd5d3a9c));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x28fef7d4fcd7b0094e11565707c0a12df92ad95ef08b898f5ca9ac1ab66af228), uint256(0x23c3c04ace431f1386f295ed14680d39a651191d14fa1b4fef3b5e8b6f2e7242));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x1620c041e5f5fdad2e477a9ba062699b1a81d59471ea390a1e0ad3bdb114963a), uint256(0x2a27572fbd3a2695b732380590744055bf22d800e8ab2761f150a7132e2e3097));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0ee5a96932a4e24bba2fafbb2bdf6d4fc130e73d9a9e40f921090211415446ce), uint256(0x217bad4a8b36f47877a94d246d1403b789c94e24041a42189fceeef09896b676));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x1b5b9239ee3fa1383d7ea095532de24048a07d1cd29f5d82304b2127e2018963), uint256(0x060da13cb04f869a2e5b86270d0c967979eed71079ad4ceeab80155e99e915a5));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x1c79ed7ebff4f7f1960dc7740aed17a32aa14e1b7e31783dc2102cc534adedda), uint256(0x07972abe4d269f984f396c3f5452489e73d17e1e5ef4a5cdb46b4ed479388318));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2d8a5e3276aeb9d34423ad8adb686d76d6659d24dbd3f975b42c37ed8c240f9d), uint256(0x0ac7248f5f4d34fcc0cb8f9650daa552ed880c64ae74e4e3ec0ce5e3efccd676));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x2776131aa6b9fa3864237f462c5d06a2e78bbb7193d8548cfe2a186081b45dca), uint256(0x0f00fbfff5dd8777b7cb500e3b4ded0d031717604e0eedf4513d544867f77b40));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x1738669615e2949c95bcdd99942f529d45a2757476be39c2f0faf334048c1e71), uint256(0x2aefadb87fc363097c497277312a3fadead57c7135b50c5db9becf079f26b220));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x09e7d06df77658eb8bf78b8237c0dd66fce6b9ee2866690ce3844c0219cadb15), uint256(0x2a2509f73360940c66fed7d2a036bf76f86bb9a0b77b603335f2ec434a6c3c88));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2a2c1d8e8f2023f2b28fef04f5ea640602f318e94e1d7f9ead84644b185f8c03), uint256(0x181e82fb74cc970f1e3c03ee54cf89c26d1c0c0a944d813578dc0e697a959970));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x01a0806abaecca2c9f4ae01d762c96963ab1a014a5dfa83d9c58867becaf3cc0), uint256(0x003e66526e88745dc06dfd174e6777b39ac31523c485ecc31cad5a263c5ca6f3));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2eefe610453b0e7ff61114c249c99d8cead6b0ae227c07095a12404e38fed4f2), uint256(0x206a188bb6d822ac516782461090ff147f597fd3d11be62ec13f34041d0788a7));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x0477cdccd5bcefde18258dd98da220f4fac42014abf46b519d60ff31c094ed0e), uint256(0x1ae06209aeed90b4ee1eff8b5f1c01115187d698a0b5afb12e84347af1d6dae3));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x08f8f16b0a86b4cc328a5cc257d3764edccadd3a6659afc6e62e35ffe8a55eab), uint256(0x0eb573b59d4a576d1c064559efcfedffc70851107f3c4196ea68209308e0c2a3));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x28097a0f66d67a6fe1d2e53d3c9d2b2932f05b03366019c955942f53c2343b6d), uint256(0x15db7cc36e02c73ed9602497f55fe127b53f1273e353b8fd943eaf53c8357366));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x04edee3bf0c585edbea4ddaadc5a003b4473a9fed05f87589e9bdfc9d417268d), uint256(0x08a5551dc87708bcbc145be291910262028f633bd1477def53b73352a10c5f0e));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x2236ee606bd1977b3c4f7c47d50eebc26ee819768edc039ccd889790f86d051b), uint256(0x00b95b91523430e72391672b19df9fde104f4650b6579efdbf1f87d01e3bea29));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x0149e4fd75e78ebc50f0269f070872c000ffe7604d3288026949dadc3896a7a0), uint256(0x01f2ebd6f71fa3f304fbee6ba3ce43b6fef0ab0b8f1f4158fea402da46378b40));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x11f613a2524cf2f5353f4e54c0dfd9b92c71d810f2e344aa90ba0c3a313b4117), uint256(0x26686200ad4c7903e6d047cfc84c5feda7e993578de764eceafad55ff5548cbb));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x109f9bd4cee8fd1b70a8a173f70f05b7e82912ec65db3dd9419c2c2156a13c60), uint256(0x0ee632fad9b7bacb7d0e4af05a87f41c899feccd9ac09d22b4e2c1b4170ea2f1));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1bac86c611ce2c01537c18c471fecec3f4595886b12a56428c437eada832c85e), uint256(0x22227a8b270413d7e74ff4e504dc48a9cb84999e45b2ffdf99c96f18c0baf361));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x0358cd067e4ee626db1314cf52bb8e57d95adaced21ebe1be24eded72b478948), uint256(0x2803b9839eb31e713fe5cf9728a6b3da2c15d6673826278debb866386dfb142f));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x1c520adc03a404b5cfb2bc6f152b943c7fe77a2569536bf4d06fc039e2ad7bf2), uint256(0x27c28d6a3047baf25d3d1cfa41a666585c3686b9db447ad698675e8ad88c32b6));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x07899c7e9aec80dfcd864dc675060dd0b999c0122b5f3660b96567f96c04f94d), uint256(0x1272630db40cf4b81d71e14d18d6224b93aeb7200133c29b2367330022d10bd9));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0a797a357e10611acf3337c7c23f57e2e0b317856e196c0936a1dd4f7fb028c9), uint256(0x0b766086b1bfeaef1130a2d5319a2c9da97f4017c0de9e0590073fe7de4d2e68));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x2f062f21348e37cbe18bf6a29929005c9ca62a5ab493b29db8bc45f247fa0fb9), uint256(0x18da8117883b5c1063a78f54e795175c21ca18d7e9c02c54dc0cb195fcd27360));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x22a41edc0667c4347cac95146c499f737a3b724b97bfb2c5c742fcb336be9ae4), uint256(0x258593fb3242f8e9b1729a942fc19b4cb96fcb7cf359bab7adca90b3129dac30));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0fafdca7dd5d66f7b65c553f8a20bcdfe7002e4b4810717fe65feac12f16b364), uint256(0x1b7a561be9c4d9b30b0f6625751d06be8e034de33e0dc0e66fce90a8aa832afb));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x09f4c5ef940cf6b29a09e6a155c8e1aafdd82b1f9b97c0ae0e5d1da4542d9b47), uint256(0x1e577d5174f766161d6cc7ec13b1d9bb9371b7425b6078892f66a3be26a0a422));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x17e479311554dec762312afa6e70cb18f0dc7d9a4a50b1218f190ff54dac8647), uint256(0x2c37b3eec68884e146cb77640a42ad84d3b10ff39c175ba2734086171742b4f9));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x1c854535133173a7050d44899d9e56f7c9a8dd19ca541cfff4e5e3545bf45554), uint256(0x0d09a9cb1f079c8c2a85e07830599ff3be5e1229102d71837c85b7e7e10c4df9));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x23a9a3ad04a771d6e4929c3a9a79bf4425d8d635772e3a591c1467102f3c3b01), uint256(0x162e7f74530237f21958e1f4a5d8faaea1d5fc80e595d5b7c5d7e2d26c230ad9));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x137f30c1cfef79a75e095fbcd7a3710696ed153fe22ecff94555140192d1a955), uint256(0x11efb8a6d8256bbaa4c761b0146fd0f9f67e09264561190df50e525dd458078b));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x19cc843ef8a138a3ba48befb5591ebabc51b636746db931b9f2e184fa6dee387), uint256(0x23cddfbfbdaa62d18e0de76946aa05247e3dad5d5562a21edd3efb4956c45bed));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x0e40e12c11e0006ffa859c94ef4dccdef1e254a2b4bb0a162c0deef9bb348fd5), uint256(0x216381e846e7862880b9d16b60e25e43384431a0df17969c165ee58ccb3e9e11));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x03dd80634974b6ceea7aabf42c83136923d4bcb144791825f29285de1b506af7), uint256(0x27b0d96fc75ccc111026732e2afbbddbdd498b9cc74592a99fca622d42378921));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x2d0697ab988948779aef6034591c9caf4ac4cb1a2d2903282163a0a324b0a5fc), uint256(0x07a6b274a1f484011ee6eeb849e2e3fdbba5c8ea90e78a450031ccf487c9918d));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x0d673f9b62705d4d84284df7bcfc59f90913f0ee028a8a78b0edac5c4b3f1cc9), uint256(0x165ed9d0af0a3e51429410cf3ec83459d5a40cc630d6c0a89d42dd15848be949));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1188bf1c6b8d8b602d17d05c748d553b92de29f10931c366a15a8eaed2377da4), uint256(0x2c69ef05ffeca11cddcf995a3a3fd3c72510f2017f462498c96c5bb87d133723));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x2cad1a0f09d685d6585464a262178b835b7f260f25db8e1d454b6ffcab60ce28), uint256(0x27dbcb2ef96726daa48975119fa790453d0c0a99c8fa134169c728e6a05d1097));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x065146508d6d5846fc653d9debe5159c34d787d8476ac192bc20e075c0910701), uint256(0x2b0220daa5f78e80657efee514b2f7cbae217a46820c10b14b0ab4c41e9c059d));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x0f570f694e2d8496956ba22efc6e24b6c446e1edab44049061775f1e7a04b48b), uint256(0x040005f113379d76b8a4b7ce85ebf7ba5354496c206c69374d37221a45eecf1a));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x132e3a796790009104e0a55438f1aa0a8b295b6df3ad0e629fe0e4ad27efaa99), uint256(0x21477ebd030f502b14b60dd337b5e9617cff90670f3af2b0d4a2b7cbb3b6f6b9));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x02b443f30b785ed0341ebd065b84d254c470a62094f24ae4ecdb1cd1c5fedc56), uint256(0x2434d0e16f64d95d42ac1b75bc0d96ee13e7a105f36c08bc54125ebcc4fcba77));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0211c5219e371d55bc657a23e852649dcab1060f65f0da276fb968e63e167084), uint256(0x214dbbb413c1c1752eb8c08410f3a0ce8f9196429b1f95c9ae615c7e9c077485));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x0cb1110a9b2e5bd615d25f65bba9d1fbc177db11701df62bdd8610832d597d4e), uint256(0x0b699aab13bbd8e7160574c8162424012565af77f3323b140c19996ae51b4ab6));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x1e352dcf12c96f09fbab163bcb65355caedf4f93447746600d117f5c5d07b745), uint256(0x10571997007c7a0fc5a92bad2d4594ed2a47a5c1a22c2e33ef7b848737bfeb90));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x14867941110b3669368adeb220f606916cf222147794e5fac170748a3a77b6bf), uint256(0x06d8687f2ff17208d3840c6d2541d953ca1cec58c8ffdbc664d9bcfb893c90db));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x1279c48d7f62f8fc710a8ee142083ecb32d67bd57624ae152ad3051b31c1ae6f), uint256(0x12286a1ad9f76533902705182809db89923c6266a91221b04cdf818ba7fe4547));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x18c4e33feccfad9e7a7649d569935644266c511b08bfe8456202abd5d1c3e3f4), uint256(0x097a87132004d3781a48a6eb0b127fa64d37e30f1d146097a74c8b1e512a5942));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x29c444a23ce788a9e40878fc4fcf7dcf611227ec42809ce2c1a995020cbb07f9), uint256(0x19d01c0e438ae0d8999ec67c9459eb59372884d2f8ab6d5be662bd30538c5993));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x20e2b6d3a721ab436f21b8e8e85bf534e1ad4ba652ba3bb329c565dce3229a35), uint256(0x101e0fc29a554cc16ac37f084c7dc303e83dc6d87919f9b0896b4261f4b39b42));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x25d3c4b44704f4fa67cb6710ceb8b4b40219517b4d14ccef6c1d80cf160cebe8), uint256(0x262f6143b406b02812dcd51da9531afc68e4deff08fc5338a92732ba61eb3ece));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x0d513eac4940b5825b1d6e4eab3682b0d74cce4ec1d451b217d98d349c18ea0b), uint256(0x27dfc4d9ff131fd5540567b037ebb1259339aecd1368818aff322b02d11abc40));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x07ff8d769f8b1a83db1952754532d048a2393f6e43ea4a023390e81593d4b318), uint256(0x1e02481ee1e5af73d10b2467d2ff2125e357dd29e34f90145bdbef216f864e4d));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x2d4cef8b2cabd29d9c8f6b28e84009029311edaec99606d2d113f2bb9d7ec54c), uint256(0x0cd05484191d5919bbc288a7b070f50a2d254f3fc72971d7f78bf190da2e6cbf));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x2005741caad3364d8447cce020f3aa1ef9781e3699ac7a6391f6df0386ec10e3), uint256(0x1eca00b27ec472af4566b58fd8171e41492c3b6786d30d1ef2f7bab577497a0d));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x133e7fafbc9b57a7a75ea4160aff7c548f1bb94634cc470044410894fcbeaf5f), uint256(0x0f495b7ac5f9aa6dad4d80524fa9cb63bcb6c0bdfbb0f74d255f8aaa6d708c89));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x0c27e94dd81b83f1a04ee286b48b3dff50a6c543811fb2119733a5bddca5ac36), uint256(0x05ff333fb1e0a4712afa71f2954c42d761c2633fbf4c7f795d832c93586997d6));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x08c33c2973c367430ae5a0d027233d41cbf9573a38f276eb0506138208331ede), uint256(0x11f0dafe4ef5ca8ee643b8ce1453cd65757cb10564e9a22ea26352213b42ab88));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x171e9965bd5d102eb2243c9a75b8f0e6e14c99436c2f1d2f63761bc57e0a27f0), uint256(0x0b41c42852b6eb6a175c2a2cd1cc7a554bcd57e4daaba987839b4eeabd5b3dc5));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x17c9b87dcae1a05ab76324217f2e506ca2fa591b080e70b7cefe169712ba1f46), uint256(0x26daf8fff8df652eae44b0d5fc43b28a9e608e764246b571c10ae7e80241db07));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x20a76b8d01e618fa478748f7d437a2b0b2071da4667d26f184721b4582689375), uint256(0x19dc9ebf62d883bd0949bff9f18cb196dcd5f7946048aadbf53625bc0ac1d167));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x2b755d5236e22d4d12b2343c7f871e55b74633b0d2f0ba194117b95c49c2460a), uint256(0x26399314d8af1cfc8844263156e9e2f703e17cf9443becce326e8682a4d54f47));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x151560baa18476022b49578c3e85b9f34322ea82fd073a0bbc30a8d6ab0a9935), uint256(0x1482447fa97be3b5fd0b90d041be5b84442aa4c9d3ad42d75af2bc19c2de32cc));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x02e4d4db2de5b75a1423a22f551bb437f963177e97b54604233ccb657811e01d), uint256(0x264066ba63350c3d7d016ba3a2d281b6332257246f528354189ca133f9d4c910));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x2c2d10e06f59337bd0b3b48c69dc8684682aabc3cb2b73dda48e479388985da6), uint256(0x1fee03ebf09f575dfaa1ba3fd3f145e8984552e9ce8795f5592b626ea98d48d3));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x247c59557fe3e2fc993cc864665b30eb83597c3dec8a3cc97a4484580b3a3f86), uint256(0x10d66571deb57b57e8c670bc64fd8b692784e9b469d258cd1c5dcd57e8503a07));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x296cb75b3ca1fdd257782212ff2a3ad259bbbfc4516481a02117f2b8a72087a7), uint256(0x1ccdd1d8521c5dfac8e7d93165cf38bc7b8a931b155b88579ecae6a1a56ba863));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x1d62f98a39affd1683178df960db996e1ee69d3098403fd7f3ba80d8ef2f3a20), uint256(0x23bbc93048ab5baa032919e942b3987866d0091a9ce60c73a681e6fe737a0080));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0e3146f8b88194362c7456340ef3b57da0b50142fba1df0248b0476255c64914), uint256(0x0311705c0c24ac5bb0cd8ebb00fd3d41faa6b3eeb1a93616ee9da8986ab7047a));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x0c76e3e44494701cc75230fcb990623bc686719722270237b397741801a459e4), uint256(0x18f1fa7af5f9019f203e7b2ec82683a5461b949f0218d28aad05b87471aff5dd));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x217d2117e3325739ba3884c204b452b15781db489851cae24936f61b7fe98f80), uint256(0x179f0cfede9ce1968a551f2562ed9a154c4951567e09f7f855fd61d93a3d4cde));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x2c518dda8c3602eddeb182416d42d0fe084ec505e53c12f93cfa10139e8fef14), uint256(0x2a1475020c288d9d4068e21b5e317cb7abd4fb60201f850b956f250fc55aa3d3));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x1b313239d527ac7c9e320bdabaaa0cb4e12c13b1d4abdbc30fedb12a3b6cc108), uint256(0x098c92dd3f484df40a569890f64cb530c1acf3440e9ac91c0d7c7fcd61c3f21d));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x1ed9832557ee542678e201617947f78b2b37fe0c20463b4ea6169cbaaa5dc8ed), uint256(0x29d5ecb7637977b96f70e4408d384de2bc4655e7454145a4554513149e750062));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x11c8f1fe2fe3af14d0928e61a2c8fcd035c0a3cfdf4949df7e9028203e49f29e), uint256(0x041e47c4d64393a0a7b313ed81f6ffe7dcb8fc487a3a6a15b8d989476bb2a163));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x073eaa611cf9c5646202ceab713da0daad3466f5e26fed9e27ee8bf36175563b), uint256(0x0a10f425fd80e904ddeeba43bd838ccac6c3503359b4b541df289c9f1674bf8b));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x2fadd278e28aa49fa4b8fd346303ab9780d64652247b6fc984a508690105876d), uint256(0x13eb05c116b10427df72c225046729a8aa696892e09dfda7efec9175bb992fdc));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x03b9fbd24a09467b2fca3c9fde48b5f535214bde3e4b644e56845d584d3b1fc1), uint256(0x02c78c5adb498f5ea2838ab0586caf0342cc26cc4774241a6b4858159cedb1bf));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x0f894f5273c286f9eab376cc1f844043996278c43b5d5c5c43fb5c2bb01587c8), uint256(0x0b7fe714a20f4155fcc0b47a60a350cafa2d61c9830069e2536964e0406292de));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x005b2cb9c78a99c594c890ad98cfe429a867d2523c6baccfb4143107cffa138c), uint256(0x2ca5199c069a6922585dfc027484a3cb52def7e9804224e1325078036877567c));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x154fa9a25805d8219716461e47db4fd8dd3c9807d0792aeafe13425be83e5905), uint256(0x22efebea27844044de2afe0bb53c1b2e640318a29d74159765f750002fcadaa9));
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
            Proof memory proof, uint[213] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](213);
        
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
