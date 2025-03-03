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
        vk.alpha = Pairing.G1Point(uint256(0x173d3b87dd6c6fa2e3cdd45d58547457b511905ef81f3496cfb79029ebeef3a9), uint256(0x2761e327d0f9da02be78553867645df9ca4e74fcc18174895b0da4a13048be3e));
        vk.beta = Pairing.G2Point([uint256(0x0a16bbfabbd17062e4345d3bdd9a2818e180bd92fec022c3e8fa46c21d3a6425), uint256(0x195db2026acba200e80dbcbc2e3dd714ac17e0a502e0bd5f5af65a5effa9fc5e)], [uint256(0x25b59437837d89ed766792a2bd1be2b052737fd583e3f6b1bee38852205ae2c6), uint256(0x187cf9778f0ec17441f69f717d0e7016b31f913c8eb633e1f8793d2c04c67213)]);
        vk.gamma = Pairing.G2Point([uint256(0x239bb2ec7091d53274785699fb6c12e48bba1816443b15997dd61baeb3780096), uint256(0x2c03cb321a193fc1d513956235890e917036a92d3b4de2d1028782fb80a78f80)], [uint256(0x0d30c8725d3458f29ffcfb3b4aba53403fddfd5b0ff5d1f1a8a27950eb1a9cdb), uint256(0x24aa4862e58ebb274860f0419617053a3bcdf3b678be2696704a0449768c939f)]);
        vk.delta = Pairing.G2Point([uint256(0x24a158f62a1164668c288987eed406da0eb6301c0826f9fdbf57ca614d39fb8e), uint256(0x1da4776edb77e78466ed2d1da44de5e24251499bba9d1d7e770a8d9313a861ef)], [uint256(0x304ba126a8c085270eb76a5ac06541d8dc4679e2f8c4d52c7eebe507a684dd3e), uint256(0x190cb4377693fd9d961ad2f80732e67604ccab55ce075921e9919b7bead0df65)]);
        vk.gamma_abc = new Pairing.G1Point[](108);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2b18ab5258b059fb0cce8cd21258a1a2d3d1f322ce20337b393eee5f0cf6e591), uint256(0x1ecb53a10d3d9e1c0e85e9ed26963963022cdff2fb21f0a518c0d68733ef4064));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0e532a5fb334b84632b3015f2f7d43be1d1451562dc07f79c16f52416199a45c), uint256(0x1f9563c19006fe0e5025cc35e40f7c67203265664f3037df37df4aed57b67e62));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2428227ceaffb497c4c07711d6e2c22e00f89921d2b32826d1ddcd7a1b009445), uint256(0x0e01e94ea3275431cdca4b0c9447f118c6f14fa09ee2687efe03cb71fc06324a));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x06bf0856e3210124a115a815f8a1a21bd3fea6ecd92ddefb5d407a032f439b17), uint256(0x2506b06e007b3db60e1a80e335535eb7e6a400988749a94c244c5516f3034979));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2b66683f697d988486d22599f8f1540b8fdbbdf21b787d745d7c8a478af432e1), uint256(0x2f8ce382960cd4beaa90566946c5ea3f8e31405c062f4cf19cd07ccfa7a67681));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2d42a85f33a9bd5345039ab8b1618c8ea71e99d883b9f37f2f8e36d98405e733), uint256(0x02ef91f214ee1260447f5684f58f3024c621203133af57128bf7a35d737c0e43));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0eaeb512c6fe679b8a0c8a05969ba47a696eb60fe65edc395a04a01e650262e7), uint256(0x039dec3d049a077b78110761c227ee82b61651ff78f4c19a58429967b8008a6a));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x21209c355e5edbfbb620e1b74287256cae7729ed0a13013092c826c17669436a), uint256(0x04009aee4abc75efaa2bd33725281c80c6f2ebb54a714a6884105406bb796c65));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x190e8c75f656cdc369637e35ed69d987a7239f14bffae8de187948ce575e4198), uint256(0x300df5c514ab8adfa9d0a0b46585604abf28857798e327693239c17685c2682a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1a37850c6d242ccf9dd4aab2cf90674794d6b261a9b054c38fb684089559049a), uint256(0x2cf2c0fd128322f76a6d9bf253053c62a78c2b31070195fb01e29d3153e423af));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x197b71c7e38b13723835ffdffc5e93d60211b98e9e4a57b3b7651f92fd7b4ced), uint256(0x023e2edf95d350da9fa75fdb4af3e32bbe324bdc4dfa854f4ee7234bdadb96b9));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x066dbf46784f3546eda99780019b1d0b127518a61afcb23f4fdb54e6de52a560), uint256(0x11ba452be95e3b81716a57936e827fdc9ef4ff74ecf0b371bc18466bb9ace93e));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x276cde865e861506cbdb25eba7cb49e1fa26e484d9328629c7afb04e89863243), uint256(0x17619af38143780d1b4762c3180e45521ac0d8aaa48baab2bd5962d42ca05fda));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0d03dfd18db30798874abd88c9db3437ee5e459e3b220458239b3acc69be5b30), uint256(0x2a2c0079d6c22d02cf3dd3c6f876af407a7df985f1d80840f8f0775a7546ebb3));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2c1f8c80ab795e86f7eeb0782316877f0ddea3de6ebe1378f1d00603f1308d4f), uint256(0x2a42ab8c1518c4a17135dbc124de9f67d468f940c561fb14eb60371cbd2ecb66));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0dac6365ca1af1839db40d1ff53dd30a3664cc573164bd8f5dc0f7343f173e03), uint256(0x012d3cc6c1d78e86214ebd033d67ee2dfae4575b1a73832c30535f186b28a7c1));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x281aa7256b0d6b846e44a294cdd92cdb432cb947a38ec3dedca46a50cc91fa1f), uint256(0x098cb5a7c43c6dc0ca1c19e2273473b4b725902d5aa55a21cc46f23b1b1a35ab));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x27e2940ccc42bf61e22c4d10a7000b401258f7ebee6b2ff1c25960e0bfe2a161), uint256(0x2bef1dacd6c55f63918aa54c1426f3c181d6053eda6d885211b8ef0980e9845b));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1e3a66617a4a43c084631c8f783e853e4247519c757030ae7acdf795902d7d11), uint256(0x2e8614133d112a69cd0ebd551b9e7c57390cc1859837abed58cbd759d42df7f1));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x00829494e2500e8d7e780b7e1bbb11d9eb8b0a5ceacc12fe06f945e46f45d870), uint256(0x14a25e342f95991109c1c65d6e8b259128e7679a8ecf41ae41f62a8c282c08ca));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2c636cb543583685264d2652c199a812beaf2d0dbf5f7be5f7eb3483d2fc3f55), uint256(0x0511e7793247f69e2cabbf8496546876ce1eb78a6ecf4fe3fa35906e7598e292));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x287281859f07f2f7b52e44066222a1b040990fdae4cb079441d3c33863ef8953), uint256(0x1b386859c3d528fea2617097e26f9eaaadd9a983c1ca23da9b24f1eb4ca5fbea));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1e2a403f4fd0da4069a42f1ba1249f4557d6192d43c9bb23fe074d82f11b488f), uint256(0x218823e4cb7b4830d4a6d7ad236bfec39cad20943673cffaa915e252202838f3));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2594f5446657ade1f06032bb673fe8a31ba9c316648a6d8b32c422d7be34dbc2), uint256(0x0858219bb61cad9ec9a9186d8b0c481d6581f7b026314bbdc4e48c36351703ac));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x102c18deefa7e276d6184f0b297163b08cd2d4de92fda30c7610f0de2fb965d9), uint256(0x02c60b06d8a29269f1902702ae359abfd27bb12d95a07b9b43117b5975f12a9c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x05b24bad998f854ca2fd8d90dfa8ca0394f3c959498a8e7cc765a902111d5334), uint256(0x160c11586d54aad6495752ae0317af0eef4104da9e6120c44a98f6c792db3318));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1c1b62aee44eddf3ef205adaf308fc6039369dc738ebd7ac824709af925bc894), uint256(0x0c1bcdb55558ff4854ecf393fdf4a33705b1c503435a119becd1353c03c3b8fa));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0996b2bcc4271029ade09c512d60df1b5e4d6169f0ee22c4d42c07a053d45836), uint256(0x13d0276ed1640444cd0f76004ae5c1910ba9a08a29957cc1552399b26246ec5e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x128ed38adabf040920d20400479e9dce41bcc9c869d295d3704b88533c2e46a7), uint256(0x1dae7d2057946b7b30c15ddd63dd36eb5a2fb2ad0b07948ba240023d7a704a62));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x15ad855bfb5fc97adb60a068a29fa69dfe75a281d8db9130070d523548c52b6c), uint256(0x141e62c11c39f295598c6e0b6d28e8bc6f74ba4de3c433f05ab259835b773c2d));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x021a58188ed74d026ec3d7cea9577c6ec5373a54efca00f6013a21bcf3060faa), uint256(0x08a959e4bcacf8814ae903a287b6f96b1b6a7dfdd82866b9a82fc25172774c9c));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1c11e07062a9f5d11b7df4b3c938e98e57a205871cf2458e3c657116805f1718), uint256(0x016a9a1913203be872583aca52e76ee2d42c7e1d62a8b6a69629e32036edf84f));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x15bdd048e9349af459c17a3576069f14657e8decaaa7ad4060936afeac1f239e), uint256(0x0e65d8d392d5a5bd3c6084aca8cc1e68029b2623112d81ff594717a03d843ea5));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x131912ee11cfc8a763a9e0884816b30f57be7371d224749120e1e7e3ac817df5), uint256(0x0de1c4c25296f0a0cf1bcd7566c919033b0f78d23083b0070bec5003a2a02123));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0e4d84a93d03208de6a5dd7c26fef59d9c75e7adc97738db73749bdacee27b64), uint256(0x157614b114140544bdfc06c597ab88aaccd1266a7188e4899b065fd177e68d0d));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x08835603de0b9bc5c096aacf8415cf68c170aa8a243a639736585384796effdf), uint256(0x3055fd81d96c0f5b79bfa98bba7142a88ebe911c389f8d39fc50cc2cb9955305));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1d3117f1ab367a193e00108645daa63e135b5c611ecba0d8cf6abb20f3fa1234), uint256(0x0ee581d73cfa19f214e72f118d4c6abc03876b224d4024fe5072ebc6463f1f21));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x27f692e2354546e74ce38028662c90972d54017bec0135b70439715c283e47d8), uint256(0x0b0739b5a6971b1b62134e44927d8fb62a705c5c26234845fdfbc2832c40e750));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0c211d2b99fbfee82c5e995e66c5a08f448712498f5c0119af9c1f73eb3ef938), uint256(0x2cea98d613388d786bac5c016b08d3476347721e7d49d785c5b4cdb9218ec49d));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x24b432ed8975ce5e04d66bf64f133a64bec5feb48ffe8ee75c8c5f40b65c9835), uint256(0x224bb8295c3833cea604cf8f142195d030a6d9be388d2c6193597072cab30c2a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0d59a39caa6e3190d22b093b218ba8901a1ff2b3e09c2fdbce9bf9f44c30052a), uint256(0x151d50b54692f24b28ae231578ad4c3b8f694ec4ce3111c8157626d695089368));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2bf815822cfce41d6c20868730beb53cf44668ddbbc38295f9d24a26c15218b4), uint256(0x2f999ce7af32e1e496bd23ea8a3018287118e2dcc466c584df97bac384b47d6c));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x24e284919ea26c2180b6c1bcfa2b9736d3774f8ede9ea66a64ba48c9e3c3cc16), uint256(0x1580491ecbc612d94a7bbe14ec0280a87c287e45640eed88f8e1252c33e9f632));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1dd8e67a54eb2a3f4fccf57b9d4a5ff52f8fe31b3f6f81d86160bc23be0beaee), uint256(0x03ec67f0ab5e77941a5091bd80cc8271b98ce13418d53d81c054bde5a873eb96));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0ce5c96bedb067e59941976b7e824f56ea0ca64e701c9a2ddb1fae6c4fe630df), uint256(0x0ca85204adc0174cb79aaf3c66f25dd3f74bf1b7178788035985aea16c27c813));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x29b9f6eb80f025ee0e85884e7c8273f46a1283c58c51f70853135d2d64ea880c), uint256(0x053acb5d1415a853e418a479aebd68581bde07f74cda44eaf38b2b3355aea038));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1aa08a3239d0dfc194e8e97b3d7769ac739362bafa96834be1a2b7eab90bf51b), uint256(0x1cf7b6b0024ad51a8261c495ba84b7afdb269dd86666eb974c335909ce9b65fa));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x161f47d4a477a668ea2abd033473265d412867a490445e7b1e6322738c7accb5), uint256(0x1f6a6c3cb36390835324a4d5d68250374c16f728c9ec9a18743dc43bca317027));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x139f0b035750d7282c49997c77b57dafe375355e115a6501ad2b094369ff1e99), uint256(0x07adc9255bb0cd0ee11c3a2b1e1eac18b96ea35badcae623cdcfe63500cde3e7));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1b328e051e1ee3ee8842156e1aa31531cea77d7f853192725dc6161a04c78cb7), uint256(0x12382f30457d90f7cf898e388db773c3ad1776daca6af3d8f22e8eb2e9b04f8e));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x23893894a3b26dd58e3d20ddc7f11ca4832b54390413eda32803d46e4beb349a), uint256(0x2e3df5ce8212cf129dc02658528d6bd19525fea75efb86ae41e66dca45e16250));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0a2ded21290c6c03ffc90da03ef4a3fb9363c981c01a220f7ac1bc7005a6c9ea), uint256(0x14ae61e497e35d4ced47f8dfd49a2ae3a906c0db3d7310744d38b0f86b5e84f3));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x22bf1d64e324130c4c252d40bcdfbcce280f7d6254bf96bd5a76ee81358bdf5f), uint256(0x0810231d3af370da7976b1f8567a4d7a0171f2f479f8366ad76dbb1867951096));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x149afa163c4032f3eb975e97bda2ff0be3ec47395c3a283ca5c341c480911c4a), uint256(0x093fc181c1dd249f11793389119eb6dfea7f7aa3e8bf50ec255385a649a6530e));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x12ac60c02e1b5123c6807c36cfa4887da7faceb799dbe4229a08066fa7f28970), uint256(0x204fafadc7334bf6ac830b7e3e384778e9e130044022b55ec170d81d894a9eb0));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x0cea960cc140627e4c4d768d76a56fb75c1d311865a0bff5138d842b8b1d29cd), uint256(0x282577fb45998fb50585d8cc66663524e6370d8a4f00fff9e3c59547bf7bddf1));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0d1bc3d66e8cc3bcd23a7b426cfef280ecb87e5aa4b8a6a7b324afa24769f76b), uint256(0x0c0a4919187d5d0cf7f1ceaa514abe7030b9aae1cf270f77cec01ef6da2d5859));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1dbb6a074fc08e6ba988f226c26f1d4a7317e949f8f01f6016ec88ad5781f68e), uint256(0x1ce310ef433889aa62bbc624cf8b8d96d70fc3c31f7566358145146023483dbd));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2cf0c6056c570520012bc0903e77ca416980b6b1fadec871a0c7ac669a25fc85), uint256(0x10d689fc4ebf507a97179a583813e3775b2ad9df61955e83e9a1899b5a071dd3));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x28c700854d82b7ab8026f1338636fccec4adf326c56483a01eda2e55431434f6), uint256(0x030f8680e8d21d5a4d6a73fb5878d4f24dcca7673376c8d562f6fa18360fe77f));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0ac3aadbab3c7b32fc039ddca7184db75ea00cfc4f3c6e0e771e187288a35086), uint256(0x0f96d18238dcfff89087c8369df95ddd9fca384ad60c1091e5e4d512791fd31c));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2fbc0ea4dd5a4d5f4b990e1c6e47a4f2507b029fad9f007252eea5879e6e8c98), uint256(0x1e5da5f77f9d73948d1572e3fe796f1561870ffd701e4833d3340ea09d250d83));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1141970088c30ae2050a550b35713a5baf9fc0c006bdd12d64d7e27973e78442), uint256(0x0699b923f0ee32a3241cff4fdcb257b6d7c2acdfa8b5f80aea4fb2b4eb453792));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x0a860f5297eb98af27c4f39454ac2d2891dc0d4d40373e8d0619834b509bb8d4), uint256(0x0fa87b36a022b3ed2784ffef15ed616fbef2f123d621d56ae8a799774d04cf86));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x246eefed70bbad1ce0f312fa0506a35bbcf7ca474e005fc4d565669fcff80a73), uint256(0x1a22209fa697fc0af42cc9657f0dd2282dd85dd3e398c6b8777bab6165696d52));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x186946d25c710004fb61ae007cd4ca861ae49c1bb8c1ea8da62a1f6b6f5b3d06), uint256(0x0bff965e704c6c752c11c15f5608f08364d8b7078e6ac95c39c0354c1b4260f8));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x27cc3a81f154b1918f0fc493685cb72abde13c2f3a6d01008ebfafa59a149162), uint256(0x2a31f66c1240db24ca32a823201b08291c5cc5e166eabdecef71ab7d9024dbb4));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x076d2cba1cbc8bae6105b6ecc3ddafb1efd01bd2635d0519e03400245ab64dec), uint256(0x252859dcabd4126a6c885d021bb66dc39bea0f5f27909cd09a961d35cc14caef));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1ede18356ad43a634a1b7b05c87cd3bda39cc7c34e3a6f9ce20af03660883e52), uint256(0x271247002c6a602321fe70c77f8c07f5427066a827573becc56c66f69018988c));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x126c24624089f67cafddc0542e68d308449efdb62394c0ce92dbe7496746d08f), uint256(0x2cf66421d818b3028e3c7707861321f65bbdcab8e6ddd7e753d3678684bfe2f0));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0fba4a812c95521cf18b9bcedd144ae22d86a74f0053ad7532b16d5d151b1a84), uint256(0x0bbcf5b0b464f83b2ae664e8ec2c77a09ee9821cd8018d57a545fafb43b66aef));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2015903cd878868b292b4d448c81244ed78a6fb2bf75d07b6edefcb4f770b1b4), uint256(0x248c51036e8517fd826ba77e5720148a5aac8efc1176463f8acaf283996010ba));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x158e4fb8705eaabae8097d3fe1c077ffda776cb075049b03cef402fa73932c0c), uint256(0x138edfa1fc24e57f7826fdf56c4e70d02ce40e940ef784c043126712f29311a4));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x1e653d62ce7a59162f34761c0dbdf951efe3b72028883ea644d8255b8e9d4e13), uint256(0x2ca43f0f35b6657876b7052cca0a463db466c21af4ba40b9591ed75c4a5b278b));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1d77b2c4551943aba05eb0034c8cd352b62dcdfc81a5680daf8f34f135289d91), uint256(0x2daae6780309d82677c2b905a7680db8842b84e066102e322a13f84f167c5dec));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x130d469d2403e3eebdebb9061b98367266d4ca9b8de9dc0d067156c3836c1dd7), uint256(0x16c2371dae21777286fc9980db65f9b05975f12d6bf7a4309d2f3d578233dbce));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x0c74bf908a7c706be33bde5953eac78075a82b471a09e97e34e343c5bea5e037), uint256(0x085c2fea38b7120695a9fa2ce72a6a9c039952a69fd2b0619ad30c8536bd6879));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x097e0116d3243cb5eec43107310206676bc5ada5c48952d8a54f2ec491aee365), uint256(0x1184ff564d7f8bb7b4cb7d543d8dfff3b0a9fd567ce645774d9f989044764da8));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0ac57d0d1e35c2872617aaf5cc7e8bd4ce1eed6921e9f28bfdfe1606db4c0de9), uint256(0x1bf70516d85bc4cf0ef4518110589e2bc90a029e93aa5ca32c93167e5e051e20));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0c46b268ac1b4acf8968d6492746638c5f4f9aedb30c64ddf59d0294d4b64e7e), uint256(0x1ff27bc0ddb4b2bf17036c364ca2a65786961d66c03bce9249f215a22b476c16));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1fca020e4f3130ac4008649c6aa184617ec640e5ccb15e23ba69621003fb38b0), uint256(0x1abf4d87a7e92515052d49cf8b15097741d833875572bf750e797b056a9600c3));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x0e75365aea0a56017170c12d5da1deb03a3f914fbf06707fd946279d51aa3043), uint256(0x1178c8776733fe85b8af86bf70def0a79ef4b56118498cbb475488a1c5dc44be));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x232974aee34774790ad5d44c4f6b1eadd54ba2e90ab8b42ecdd9e1e9d46150ad), uint256(0x1495820b614a3710e871c7f6078367637b710cf401260479e30531f481d483c3));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1b375b24a7996244f85643a5a68f1c54d252d25692164a03f0b76478dcd6bafb), uint256(0x232bb8365c082554cd94f00850dde5f4483058cde98ead11b90de1e945c67062));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x00a5647d4ada8361c0ba30564c5069e421abb6734639dd16e338aa8ca2817ee8), uint256(0x108f436b23ac2d306e8bb9fe01d21d1f4713b07c1f158a72c74b2e9dc745b725));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1b6ed4b36b7ab28d03abc9c1e7b10f8f3617c6a5aecc841be86fc47e832b0d0a), uint256(0x0ed8fb063d6237627ab2d63620d8c5914ddb5a34cc099cac378503aa9429ab58));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x1c949f6a598691818ad624a443eb963b097ed47400f3c47e4ba46a575f10bd9e), uint256(0x044187d0c65cdac2b1804ef73675b369356727dd575fdc6bf58f8e787a95eaa1));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x07b86e54a2835e3a34d6cedf4031abe0371b01c440da821d6cf43e94c2e875fa), uint256(0x1e2fc77927ef24b67b6d82315d851ea3a78c1f04bf68e7cfcedda2df291e98ad));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1304fed7a7248abde0292f4b3edd96ba025c6f5e6c71e993f9c4f59bf23370f7), uint256(0x1fd272d9fc0aeb4b0703d6df83ca208ec20e28c57d9860f3b9348d52b60932c3));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x010c3d9a46c0d3c86f2d74294c310e44364cff93f2d593f7750ef205a8624b8e), uint256(0x1f2481e4727075eb4d9c2669fd42d716610899e9b759cbbcea5200980a829c1d));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x14ad18f88dda8d73bb31e99cd2f96a2e4ee1d1b04a840128964780fbfff9f9ff), uint256(0x1b6a4d12600a751c4e8402b5e6616ec01fc75003a748fc1d4e4df6fbf509dc96));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x09bb2cb218d39fb56ba52d3e06194126c160dabc69be84171b9978b3bed41480), uint256(0x2e695d2ef063c7e10db7bff623ccafe73a261d3eefe93dc27940aada07b29b2f));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x18a1421249654d3a4bb2f7f2373ffa0f17af8697e2dab022b79aed5772b97ff3), uint256(0x148b0b702b9a4e5bfce7d35ea01566fb4690939484cab4247af8c0ea972a265a));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x030cf242662d81b443492120980f70a3ac1c7c590008932c230a0c93b3bfee6f), uint256(0x2176531788d65815da32e68bf06b51a7d8b6005cc9a1e4501bd95b4908488c18));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2b17be987b79c86b0c70be550998b8161229636cfa8d949dd0c1ab5ad830558c), uint256(0x0179bdeb9c5ff8734790d0df11208bed605e8803636f9804c66f4bee226ac2c8));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0799d6c48882803f5bd22c8b906898cf1065ee6c77da8828e6d44c47f9034bad), uint256(0x0a8fbea30b3ed76878851607790e59790993631e5074af187379d1ef81d4f104));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x19200337274c9e1d8a09440830dd1a47dd92132c0726cd80cdb02057502d2fde), uint256(0x1480166db621ea0be685fb5fe03cec4d1a0fb90d4446c475906daf4e4f7c6211));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0f232f6b264effc6ae6e624864f5c4654da1b9785b2444489123a296affe7ced), uint256(0x056e3c9a97ee1682e312a0faa70e44747b34e4a14e32d3a941dbb36eafa8c601));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x12df7394bd0f70bca20b741ed61623889fe1c7e4943106be91b08072ab561b4b), uint256(0x1fe49a1b3bb7d7b3ece982e7674c833ba4d965c7b5fba769edf22858881f9724));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x19d5df7309149417f7dca5080738f20b87da06b5e96fcfa18fd0659b9432de89), uint256(0x1b200245898c951f57fad3be65cfd0815704646e003b64f4120ac740f53b1930));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x059e978dad314d9bd8c5544c2a05f054cc67306c75100cd52b0fa42d3bcbd3e4), uint256(0x0307ed6d4e73f898e963ce6eb99f3828d637375cd8ac99514b16d4ad6ba96b43));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x3019fae6076268c3cee918a2ae31589cc6f509babae0d59e6f510cf27bef2b77), uint256(0x1dc67ef935c81e3ef80072e6a2d5bfa958245bfcb61c501adf0ae6280e928e37));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2501608e4b2474c97e2ed95f5e3c8b5d7b025cad19e988afb6d8cc059e4bf6c1), uint256(0x2d3802cba89a6c70952655a174241752992e817446e3a3c43fb4325388ede30e));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x193b8a9d2a126bfd9c843b114bcad5af43e050c3e5fde427ede7bc47e064be4c), uint256(0x25badbb3994264486b4a77728d778d8c661fdc492d3e881a7cd8edd1881ae66c));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x22c82c878bf3507631f6c1ce88ac2b2858ed7049ea5536ea713627f8b3d3e9f6), uint256(0x2f8dca92519ffd5425d46bf00ef9dffc18e83bfc1548a412b59e57b6faf4db42));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x05d07d0a17a3eb924275a5b3e59b59228cc370c6045afc56d1615295e58521e0), uint256(0x04946af32c586db9e36e2196d469d720b7f4b0bdd6e79763edb95629f2815438));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x12b78f507543cb0934e882a86dc9b1b18d25572134a577a402e01d9d72e0b40b), uint256(0x0f643ab3548a1ffa7158dc039a77522c5d22709d3cb514547bf831025ef60021));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x00e002558016affcb015fa6293fa506a278feca5e8d7feccfbaf5d930b5abfce), uint256(0x2f5289032959e38703f87efa52ed42d50b080944615111d8c12dcb5c4f62c389));
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
            Proof memory proof, uint[107] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](107);
        
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
