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
        vk.alpha = Pairing.G1Point(uint256(0x150b37db3cf410fd8d4dccd593fd35a40d7543bf60cb38db7bb43edbbd4ede9e), uint256(0x0c311b1f14ab5f32b40cd6e1514dfbe19aef5be8f2c14e341aaf20b50409a109));
        vk.beta = Pairing.G2Point([uint256(0x1cc16e20e4572549baf9b05db0d0649687c1da46b0ceb72c6d9f2a721b50c4d1), uint256(0x2c1dddfc8c0052752c6ab132715de3c29f1ef21e3040aba00c596ddd7017045a)], [uint256(0x2127cf6be26a2c09a39d44859825905f59fd80cf138bb518e8bdfddb440fa208), uint256(0x1e8effb28db1f4cf4842b4007c41c7dd4f7cbe528260c2ead96caa13b6cf3f68)]);
        vk.gamma = Pairing.G2Point([uint256(0x0347682c67c74c4601435763ccb7a47706738b086876707104e694a79e734184), uint256(0x252606311dbd5f2714f7a2931f769b9c2b08679e0877dcb2a5b8b9b3dc98f80e)], [uint256(0x0025a2e5e44417bac52c7839a214739cbc9adc7b98676876e51a3238c3c9ec7a), uint256(0x17890dae320e0a1bc90c0cac970f6bfbd7683a88f45f29ad51fcbf070d2f7798)]);
        vk.delta = Pairing.G2Point([uint256(0x1aaad5c46f46dbec6a647bd3adc96c3a44b2b49ced6ac2b0e5758b661444cf97), uint256(0x186dc1471486b136b95fe200aea7fbffc32c291776ca14db6c8c277093caef9c)], [uint256(0x1ed64b686da8a2dbd924fe8cb9a706e0788a883054d2f5d35ce977151c1dae4e), uint256(0x2e1965dbab39c392557de363f18a84b7067ea4a8de1314c9702fa8f6b722ffaa)]);
        vk.gamma_abc = new Pairing.G1Point[](423);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2ccc7611025e70b3eb71e9cc379f6fa21f03b0a7b0e9ef209422e1e8bfc24838), uint256(0x272b02383eb4008d1201bec29e835eddbfaa2dac8b5d23e908b7db19d83f33f8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1a70eca4cdb87f1171131c09cd16f1e542a09d86d4f4a36c8a5a29ddacd8ea89), uint256(0x02f4324dbb96db739c7eb8179ed814873c89898bc143e4ea221144e21e185964));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x03d51c0df060a3c6fcef519a03ce4b19193061510692902c82476485e0fdff2e), uint256(0x0784d26e70f86e535fc51777cb7bd700b88e76166db039f44a40822bb97c05f5));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2b38ec678eb896d2a72e557ade747a8aec3439e180bba820b2dcffc21614c2ae), uint256(0x2175fc27ebb37589959dc5cd17a91e7cc65a2a9db6ed9b920863df3486bd70e0));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x010d8716c0fa985b9836e84d529a43df443821402364371739bbcdbc42da13df), uint256(0x12a79005caa1584c86a04e74b3176505cad922304628496ae6522593aa41ea9d));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0cf566d0780a8a2af7c4ce67b2cd85bef18311429e48c23aa598b1430be8084d), uint256(0x064dda045dc0aa41b7adebef84200fd5b8d582796bc09220a2da47bacdf8909f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x09678dbd194445685eaccbab34d9415747e389e17ad73ddee3215619391e7dae), uint256(0x1c72be9f89a21b1a32616a1e92ef2554994dfdde38161a3e38436546a6394d02));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x181179062f20f06123c3b09a965d1e5da4db11c7ae1c60c884150b6cfa6cea76), uint256(0x09200e8431d75ec43e5995652362425367a72e47b841aa7e23d9f1b4e4457b4b));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x229a3f7431d6d5403db42600be7a772bc8cc6b79a75d664c752dd1b2026e526b), uint256(0x2f500084cfa465135e6608a1ce34f47b1b7aff7cddeb8c7cbe162b74c3a7356b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x184fa603109fabe31952c63b67a56c8dc5fbd0bcba77434c78b933d6c0d3b0d1), uint256(0x0342d152259cd47984c1d9a30b4b9018cdb90c5d701bbaaddfd4ce91ddf90096));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2801a5f5854e79db678c6b230aacde84908ce22a96be821ad8e941d1981b4ee9), uint256(0x1a44b01069022d67e01e77247db2f3f2bc3fd4d7b3a5b2ea9f7d9e059a697d2c));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x05ce83f47db9d50efa463e5ec105863f5a050a19a2e47afcfded51cc996fdff0), uint256(0x0038c992b85c622a0621a520dfffab48c5612b2078848f6391b02eb452001f1e));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x14c49b55410b21b65a01f7ef3c49f7a18e7207eb5d3d9af98b9613931d0d30a9), uint256(0x17e8d6f604fd7b23b1ed97d62d6c1e7f8cc6cf3e00494ce10bd155cd3409b597));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0a1e0e824f7cc85183ee7267f365b949aecffc4eb96c5c290c272e28a9751538), uint256(0x2dd1d434b5b9f02e8411f48840a1ef245451af2c2e41ab04d3786fa2a572295e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0485b2c7d25a6f677733a63199dd42c128ff00126b28f474c61c695250064a61), uint256(0x1424a1af89093559ca9ade90c18ee569c7f28ccc02fe0969e1079628a40ba13c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0b3ac5ef2d1345cde40b4245c5377c2cc78039fe4c06e4ebfbfb4839aeeaf61b), uint256(0x15454766de6d1436ea633b29adb78a4107f27918e6fbf8177f4a8f110290bc68));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x25ceba2af288587a6bd01ead00c3a17012c638e137a441243bb53d169453640c), uint256(0x1076cb13e39d3d7b91685de121fd870b973b068d93cce339f39ac48ffc4e5f5e));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1541a70246c19cfbd34a432025f6e0beaf966c219dee7c0567d3e0b1805b8af0), uint256(0x2db4f27084b7a1d5acb27e4f99cd9f540b213deb1ad5da46f7105b677181657e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x18bf44b0d62ab87465c261cd1a43a39def50d836eb733aa75e7c5545e3ef16a8), uint256(0x153e52b7480c372e5d54e43e9f70dcc3f0e884e9d26aba488fd93d91a49bd6be));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1b84e44f3cef0d2b3f65e189555621356e21c01dc36a83a98238bdf353bc0f02), uint256(0x01e2e8f40adeef4415888be0d6239009e6110777761175a551b925eb385394aa));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x192584aa56f05d210e8c89de629d406402b115dd9adade900c7ecfb60dc7eaae), uint256(0x292c36ab2d75fd5712ca0d3c86813d5c7882a8e24a15814e6342ad4067250825));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x18f3746beb4fff5d5afaed8b9cb618b382c0dd1f8e56b678bd722950c8572cff), uint256(0x005ec67d7682b0282ab1ff8f7b010378c8e1d85e82db74a1fe51170e0971b31f));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2c2a6790d125ba72f7b3cc42d5d493360158c6a5315d24bb6c350f9f1991b579), uint256(0x1a37dd22fdd2da66b0b1ecec1fe3b92742a63a8fc742e0d02bd7404986c5120d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2b39d14df6725335c6e18969493308d49dcf7e3bf045fe696f7cffb4f6959530), uint256(0x0153d3308a1ff31580bd1b2b1dfd5777bcac3cca94f6a068e4721a018c5bcab5));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x039b6cfffee6b586cc6d8e5c9a48a7d599c6376be25105b67801eb8f68a3e96f), uint256(0x15dd0ad50dc6198eeecd85234f0726934582e13d222bd8e0170002a2252cfaf0));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2bf23cc3a940196a15e838ceb0908519f476dba01bd55ec5ed4b0123e31e3c32), uint256(0x2cd5949b1c6420f9394e2bc9c0e7a39577995e31f7fbb04bfbe90020294910d7));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x09f02ab48eb064e5310eaefdbbe1bbcecc979b0d8335977c4c81dd779371586e), uint256(0x1a1b21be7bd773a6c06e61189ea8715bf14c7a8ca09cc366dd25c18741c43417));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x27b0d7943a7f3e53de114a28af56384e5783111240eeb3d1dbc5285f7abf91d0), uint256(0x068938935e04db6fcc1d4879038c1a578b04bb723d7060100f98c50270ceadde));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x22d713c1606a112b99e7b0cbb5a760cb835f725c8a8f270c2558d3fadb53726e), uint256(0x2d166633213d78f73fb4d047c2c582e44478ee94423a981a1464a5be24c46730));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0fdd865d3f623fb65186d15c06108766e0602011c143d8bbaf44dcb0515ce5cb), uint256(0x08f46cf9521dd511408d58ddb39a056c6e2f00357db2f347f4c5a5cb9e0a8f84));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x26d7cb19f09e64dd0f209620d508e04b377adfa3a4745e68ffc8ba5bae508203), uint256(0x11adf097a5da5c34fc8482006566faf6a665e872441537c72393be0166332852));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x26906408287eef2b4a731d80d702a9c6df17815b50abe242397ef81215a4eb93), uint256(0x0a702617871ddfc11b7c007f2efcfdcbdca532ed9f0c981c49d98a27348886c8));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x28c30890f82b54ef492c9676144ac0b3cd8a2ade08597c85af3db0ebc7d76dad), uint256(0x16e9435bc7dc175043f68f8c4a5daebaa0418bdf60cad06cedd595f8778cdb66));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x21ddcc6edde968528426186f588d650331d8ebc415f31f7eb37d4105889e4e8e), uint256(0x0df2767bd78996b1c9d3991ed5eee30f869a9700a922ae35dd914a4dedd6fcd8));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0be9fbe30208108af9e810dbdb4511e5ec13ab7b24529f3ee6ffb8b82101d0da), uint256(0x0d9459f54be7756f1e40d74afa158fc081a6fe36182e5747a97173a18695c28b));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x03484b160510fcc82e0fc9acb32f5a96eb0f97907bf831381ada1832883a5d18), uint256(0x24edaf67cd8a49b6e914b1f3a5ad0672b64deffe330b1f6440292701c84009ab));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x11498a57c3a7f5e55ac39ba7f83b918aa72e72114e7579f878051bb4684d0bc8), uint256(0x00f53658004905c9397ce2b39847d6451969ee7a814aa4b0b350ee5521df0417));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x00907477171f3b5dcdd06e54aed737d28737c722da06599506f3bffdbd38cc21), uint256(0x08de014e5ee6c9118e975425036705d939ecf758c3e7328a1c3d61e41a10245c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0e1f6eaca59bdbe8cae6fda1ecc5bc4992a7d2191c66c41700d803313a88f0b3), uint256(0x050721fbd24260a573aa09bcdc608a4059d6f644cbae5ab562a2988325587351));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x224817913936110d3303309be2ca79fe8bd52f2f30ded8d52124488ad0e13ba0), uint256(0x0aa7278d8a6ff84c9907e7d2ab33608ecb11b1607f093e6c23da1bfb9696035a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2a771ed1f359636b9e48d4617f73ab816da261d62b663ccf89a6f16009ac610f), uint256(0x024e925c45d9fd97cf303cf9e14c2c293452ac23a820989c2a95faaa97b7242e));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1764c47b267dd5f37495ce51567d015f1567a7b19794254f361e5f9bae3f7ace), uint256(0x2d36a9f5b9cbaa5bb628071aec94a71d87dd1474cbf90e6c51a13b5f1a117f00));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2af8f6fd3b0ec282de0e9f1e2fbe9c9d16c4a105b28c21826f88dedff0c45640), uint256(0x25757cbd0c4b5ad0001935adf9b667a7772d8525058d56e37f0c6ea9966699ee));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1f8d77406d95639878c1c1547e66443acbb2599aa7917dff00f4064e9b80ac6b), uint256(0x21ce3e2d9c10c8da10912e4634c5fa85ca30c00f106fd7d70c7bd8b6d61a608f));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0f20f3a7379349617499d8a72835f658a9d520a74240dfc1c6637f9e9d2aa559), uint256(0x0ebe6b17444b28aa91b4cd0cf592d2c8a579575919a8fbfe397bf6c03126e783));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0e075f09ad851d7bdde4bd55e368fdf4c9ce2eb9a0a32e998153acb116fbc61b), uint256(0x28209a5c989fcf3a7ab3e22427debf038c65dce843bd0e22ce6024fb3f9e3042));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x02a62c6570ee21288eeadfc4926e2ceacf1a59e6699896c28454c5a952bdf219), uint256(0x0588b207cafac82c40d892a0078ae2ef1736b0fa22c88b9c5ebdd7912eb77d03));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0d3f5d42c5f47d1952ac69063704d2f0d9b040ae065939b041ca97ec3a4217d1), uint256(0x22f22498fe1513ec8f4eb8bd298a269c5730424fa86035dd932f4ea3a721a107));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x11f02cd8483c869d480db93f4ceaaad7ac22e211810425a4482d08928d120385), uint256(0x1a14574a50cb95a9385350fdc7a1e6baa1b70a90e212d830cbe249b8f319b0d8));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x23cc78e0567b31a622854a65c50b7e94de929bbe42c94498c287d1d54a0509b6), uint256(0x290deb1c226e77d6955c16430f2a9c12a2080c88c4362582b62a5ce9efd292d4));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x25eff2c604781892b1a8f5b1d6394fc9cdefad4618e5214020400eb7db708bf8), uint256(0x0aac7e01e669cdd8a27aa75d76bab06e5423733b8e6204e7f19843503a73847d));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2eabf70263ec09f82adbfb2779e8f83812fd0638de40cdfd35d7713b924ce0d2), uint256(0x07c4f81c2ef1974d0b0b23c94a0d57a61211ea9f131fe461b487d8089e51b5b7));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2a25028fe5c8ac909dd904b9ef5894b92eafc9ef05bfe1d96287860dd69e0903), uint256(0x102a274a5648910af4bc8320da8e0bcbeec24536ae8b8f2b9ffd0c0755f7bbce));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x048d84c838b3df027574eb6665387fde3f19af95873e014b757cc31e676c9a66), uint256(0x2b5931c3dc3b34c6af526816be81ad7b2091a604c108156cb011e93dea2d9af6));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x01e362a2180761d7c7d27c3c4eeb1b1eb0d5e2d33b483617a637c40370160c71), uint256(0x150c6aead403be0942446d7bcd772c14b24945e7529c7a51ddbbd3d09dd12e4f));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1b474da418a94968b90e4c7cc282e9f341b3991848d99f9846fd86d66f7b280a), uint256(0x2212e0385e50cb604560a70e0afbce07931c874d77dbd9edb89cbee734348b8d));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x2631ce70777f609c7f76ee6bcc7317cf2794fa006a25767254218473a0c0cd20), uint256(0x2643a34ea0413941af056de153c37674d3c202a23b0fb1ccadf79bd9bd3090ed));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x248b68d026faaa2cc14c99aab5a5bbc142f828d93faa64c6b9d0fbedec41e2af), uint256(0x0a7c5bc3e50c0d151e310cc8fe38b962cf10048e5deac3c86c99a408666cf5d0));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x289b0e81d1a0159faaa557ca19a745d1a4699758ea4be8041c05584b7ccebfa2), uint256(0x008b184b5335432d81a974f3c079f17d06d2c2aeb1ca05b883ed9d0afa793289));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2ed17876d469f203423c8336252ff698816ba58c83a56e4e9b29aeabdcdaf929), uint256(0x2d392102c22c696acb0eedfdfe3f28dddc61c6f04b7544c77c3f44c76efb11f2));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x19dbff8eae64ab9ca45db32d8b4ace9fbf2e3edac62482df8b889015a47a56db), uint256(0x0ae674c9aff636745ffcfdcb5d4c27a8181b0dcaec3503de4271de536d2e5849));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x13666e28f10707eade97c0f8eec85ca3819abe694a954d80f446949445ee54af), uint256(0x1536ab6d064d454b2bb8867dc819ffad9fe9e45fae8828334f09a3dcb82e88ac));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1f87d5946a4a69e12696ecc0fe2b893ede9554109ffffc4c517af2ac38888aca), uint256(0x0cc096c478540fed46d06101ac503dee6c3338e9ca870bb35d4a96703a6aa0a4));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1543dfb64e437e14c00d29a1d0afaaac3d2a540515307640738291f8a4ac3b83), uint256(0x0b3b5c9d12c19493c4b33164906fab2a0d3dc54b9895ccdc7dc1794a9a3054c0));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1409e586af3b22e49835a06dad721c03f19f851cf35b8eb7dc9d499e2c9ea869), uint256(0x26eff1f9abef6df3fb9ff137a0f5af49695e863de4a9f08b113cf36062ce6506));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1613f9218f704d23f1f79d438567d97e5c7c67d63b139eac1ca20aba9f6f15d9), uint256(0x2563b5465f2db6dc4c89bf3ac49ae70d30e1812c6be716713c4d011b4a29a790));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x056ed651ffdf09ca7048754a04745a0167d10c63b0eb592aafc4839ad5dccb41), uint256(0x2b78fdd20261716f483e01e0dbb6f7a6bdae24cc3d11b21b4cd1a2e62d73b7b3));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1aa4cbb634438c551c49ea48b3ff9a5ce1c64e6a048e99302ab45c738eaaa0b6), uint256(0x12269347ccf467d6884e8d6218fece7dd73cbe97d138290a6a78a2d1d57ffb16));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1e8d40c0388d051a2472f13ef58235e208a8983b81f8e13fcdd766b5acbc5a43), uint256(0x2c4b8024fad9b8316d67f6ada33b0bc502df50cf3d2c9d119a36f05a38384e1d));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x000fa9cb0be3b27f7e36e9485cdbfd6b05dfd7b01521a9f558e8e95b26a8e694), uint256(0x014d42b98cfa2e03e947f078ced9c587259328ef499781aed76c22a41ed26271));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x27caf2ee2d0032bd4bdbedb88d7d1bc80c969d6e6172452915f948d8edbb2862), uint256(0x01122aa02acddd66e3465b9f85eaaf052e1d29ce6aaf96f228ff4640af4a4db7));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0466ea0944adebae7b34b5ac7655f718af2c2bea1129dc941569bbecf66446d1), uint256(0x13de9989b185b637ec585e9edb19e60f66baebbd110d42f91e0c8d87b3a14ddf));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x228116c71891ce7b0acd9d8f79ed39cac6d5810d220095130bc009076973f2fa), uint256(0x11b236cfdee734f9c93d7013cdff4e96625df7606a9de9c25c0b09f0b89e3cc5));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0a0577de8d67f23e55bd2fd6c99e4c45dfd659007b8a9c3875d13338348e2113), uint256(0x25c441b565cec99b87291c6190e196dab8276823aca0427b8c7de6c26303d0a9));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2f83496ede13bb40cf6ff81ef495b9407002e68e4cfbbe3d40edfc670951640e), uint256(0x0995791712833f4dd660632869bb25c7443f4585ffd13e47cd017d070838d08f));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0a3c7fceef3726547261ac8bb98fd7c4f7abae7de4c262d2cb7e2237f1c091c0), uint256(0x257d14bfab58a471f97fc2f9400d63b1fbd5be3e04dd5aeabf71a7d24a6746cc));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1241ade4b087edd2961c3f00b8d62a24b89cdc08cad4aee0a3a8db5475419d55), uint256(0x2ca4dd8766e131c7594369019e287ed3e58fe683c0c3aec8f824b43cefcd4b79));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x19425c4e8cf4fe7de74eba83b8a627d2a15106697322f87fa39b0cf4883cf244), uint256(0x02b70cf5282a75d0302dba7e3bf4b07cbd7b4e2fc37439d31c2b15a1e8e060b4));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1c74444edf4e021c0a00fd00682a1040dccc2b8e9d0f9cb2ec2258074d438642), uint256(0x0879b786c1f3798b8c01ea5da441e38336d05748accd307e4290a32992959f18));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x19ee4ba3ababd1149d22b314a860d6d901b5f6b78ea20e99c6d1440e9031abfa), uint256(0x2607b857d61aa54ab13d28697b91917717c5aaf731b2eb5ff7514269d6a1d634));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1a6d9dbb111164c4f12065a3753e66701f020a510702d845bb88c0c0f47b4d9e), uint256(0x2b7e1e5d8fbdcb4d9b218b9a1500522cfbd0e4ac79e558920e3e8cc7ee3d280d));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x00c1d19da5e763f90e00e38395347351090428be4450555ea6035afe3e403a16), uint256(0x2d0c5c6fa652108f4b3387eeb615768a80581536d1fa282d7e76348294b06233));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x232ad8b556c9ad4ef5e0cfefe28b4b75856bcf1cee46bc09963b9d48e03761e3), uint256(0x21a8ecd52ac18ba9d36e3c9b0a0844a98a5bebd9ac5a964ed543eb433f954dd9));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x115e28e765aad543d1a1776b8fef4ed10f8333c13fea7778b7d3092aa10966d8), uint256(0x30365e17c8133b3547732fbb5b5f5260bd91a83b412bd7c9242544bfd401bf36));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x04c81736eb83762ae405e92fefc6adee5471b16b4ec58f21bf3288d044e000cd), uint256(0x1be14980ec983435d4f3fa0741f0792232dde21a88bb2ef5e7f4eee5df569f9b));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x12234c7272d7435e064473fc12f1208d5d519b4a698856e4e09933a4d025bbe3), uint256(0x0b73196fb66d70e3d24a3d8058dc530430de3c850253098ac08417978100e347));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2b95791992d1603b89421bf29a4108a7bb04d4d6058b01154fc80a1fd27c415f), uint256(0x056df5344366f39b8109942e637871563a5e5e4d4869661322c1433f98a58007));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2b38086b5ccc3613afd54c40efe36490de306ee77a6f7b83722697f063a9dba2), uint256(0x282f6b7323651910980e485d035247570def3d0cb247a911a7073b80f91d03e6));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x27dc2bf317afbc38d7c30b75b0936f947a1f457f6a210ec08e365377931035c6), uint256(0x2078fcc9f4a2cb119556f2597206c3b94ece2031f1bc91afb913dc889b52cafd));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2fff9e062cd9355c3a1b41e520c0e66053606f6e97b42f38ee68ff4d077ba940), uint256(0x2183ace5aa2d5f401976181efba660bc947c5d26142fccbc3d307d8d93dd7ef0));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x05d00927b82b94bcda3b9c2ce74303e0b6172c225d9b147ffb0d9fe4323eff0f), uint256(0x2f2d8ab1b68ea88c0fd815a80d34945c0e8d80713dd2a251f2ff1f33b02ec246));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x24a78c6edbc1a1209dd3a4d40a00a42ecb15156e474723d423dd2fd0043cb81a), uint256(0x1ebca89a0e0c5cd206f71d53141a2863fa4ec60cf260fd1df98a59c12c8441f2));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x177e72e49128b5d31cb2bedb4b3fe3fe34134b3d866cef94faf55db3d409ae4e), uint256(0x26e856639c0394e49c0b3c07d05a4761c7de1057368057d942164a45aedd2664));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1b8d2e131e045c00b820e21222991c0c56fe77874e390d1f764cd34d5e0b28e6), uint256(0x26265339ddbd67c21b9b142df8b7dfb9c95520870757946c3b163f0e8ae3686b));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x06c365c966ac82bfe70103bbffddcec3248944c75785fc444102394cefdeb3ad), uint256(0x030a3a719f65dad1f9c9ff1b5245916c82bae80e90abe0329ef2cd223bf08572));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x015e23de2587dd59252d6d14affa6cb498b40a5c80b837465cc1061368f39216), uint256(0x2ace2ce89608747485a53d50288314634c2cdbfb4873cae99bc401285fe271c9));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1452b79a444d9617d54664b87fa6af55fa7800286187a88c15c2c3045d291a26), uint256(0x108243c7adfc8527e71678835a774dc922972487a2fc7493312fd601b1b78662));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2845f08d2e995a42ff61019dda64083fc122a22c395a7cea34637bda12fea846), uint256(0x06bdb8404c6df07b62de5f74abceac12a7b2101650e071b96cd8ade6cf90bd21));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x304524545f70b57a883989f037db39d8034348b39c2561e15dec8084c7bc9c9e), uint256(0x15b2b7a19226033de0e89eb7fbc42bcfe8918217ab0b20469572115fb4368312));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0882aab8be4fd0816b17c6906f9e73c6203d19b84d9426ac0b87f6212b81b602), uint256(0x07275e4d9ca7f9261b9bd11015c258afefa44d0ac08ea2878de21860bff28d1a));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2a00a9f3a1cc018eae24e936bd865058b6a57c5f951b9c9c4ef0d13b2a956bde), uint256(0x13f37b0b655c9208447165c500819b1f1d2022c0942f473e88ea2a66c553db62));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x0547dd5e702b8ee99b1f3bbbc118d3ec43a923655402e0becefdef05d261f73b), uint256(0x0323234959218993552d071c8c7a74c99d9240a9acbf9eeb740766c867260d35));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x209dc3bd85fb83f1c5e36425bc831be0b2259a421232b7f1c0e2916cbc72562f), uint256(0x2f3025bf6b7293742c080bee444e8b3a112a7fe56e899f74cdc500af33036d02));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x1f49ccb175dbcf4a0e296e7f0a4c6ebb8db72ab8897f6393bbbc7d0cb5f7cd57), uint256(0x0dacd0a46baad607574dba96f6d8be09475ad1222cc49824fc40edbc548b17e9));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x24eeb4d77f88d84d321d9211b84e5d0e9841e40cd60c7e77858707a0e11f5cdb), uint256(0x03c3756d133a11264f5273fc66228edf21cba1d8433c7ee71928baf89e0a8297));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x135907569a2fcdf77c0a47b830b780d3fc10f0932e6848ae3cd77b3c173ebc1b), uint256(0x02a0cc4176ea7441af04ebd9b90bce8779b82df3ecce43a5ecef374e4e959e16));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x297837959b22f9c51f3472505f0174f697dca0e461f5ec41a62ace8c637be1a2), uint256(0x26b017b736495b95c599decbdc8c56d66cdee0223f7e6d820581b92ea957ec46));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x2d0c8d5f055321e905fd50c0adfc1667208b0955213679a63d1b1398d95400dd), uint256(0x08999f086d310e6a7665b81e13e9738065ea86adb09b8b18b3572da0cc277bce));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x0fefbcafc5e96497ec3fcc96186a601df6ac7e6a22ee5553c787be88e9a28d46), uint256(0x06be19b75d04be9fbce03fa5d27bb7fd17402eeed5706eed73f56f1518e33e31));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1431379fcb5ba80c1479dd7e082ad5da37c86440d8c9c279a980893ac7de4aee), uint256(0x2c3ec627ae03c4f262ef6072b8f2fbdd1a13ea6731da061c6ed19b4ffec3c050));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x0f43356129bb084accbb2749e7971a54e0ae1858a9769676b93bac8cfa6bb248), uint256(0x055bfe83896c4cec8b51b1290fa7c12d18cc8094041d13b445434571b40fa89d));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x1f7820de42004e78bc07005796e58e509119c8409bfa98bbf1e69f8d638b4d57), uint256(0x109750e8c06f4934f93c952e481c49e9678a450a31f169de4f2f921e53b254e9));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x2e1686255a4a4e032e9dd11e80b08c8172cc10a237540c7efd203aeb33d3e353), uint256(0x073731bf62ee0f6edcd68b1fed916d141da52ee3fcc81b44846f21ce1cfd2082));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x14f8cd84d4ed460b7581a357221389a5c23b3eb9310ea30d00ab9b21a2bbbae2), uint256(0x1959c71ec28cb3eb5b1ba4ee8e7b3dd2e2029598fbb8d1aa5db12f00ded5d791));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2fdd6745956cb417b16325e4bffda82c07ed6be0d16e7822a1ff9ba1a0c5fe4b), uint256(0x135b7af9404d5ecf0fb3306b47a796ae9682e1a7e050d250e610699c2625b49f));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x031774bb8f3462d094d73200b1cbc2a33ece3c842be472359f5b113c90920100), uint256(0x2889c531b88af028898199fc6a8dafb6534eca84ba4a5db561b13723991d4cac));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x0066a1b4328ef26ec80aab41c1c892b18b9846a95c99a35c6d12a063957aac4a), uint256(0x03b438908232ca00d567d1188898387532fc7240fcd531f404eb6e1aa42551a9));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x20c18516b8ca5e4ed0f88bffca4ad6f3462efceac78ee79bdcdead0aa612fcc0), uint256(0x12ed0824523bccfabb31ef32ed3a9704985bf0a6c51e70d8c50792d89c7dd613));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x0e3bd8a6e9ff915b69bc0ea4a7e6b41ed551a3f339f9900a8c77068bfb95ecbb), uint256(0x11e788099954dc1c6a88932f8d033a78616b4597f85ef103b02d72271dc6f421));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x042475249cbcae345e5a44fc840ccf8cd051c938ebdb4a4ff20ce9ae8eb2ecb3), uint256(0x0e34e49bd022ea0e45782f9a9d98e022f1e194bf93427af17188f9d14f0dd27c));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x033c9548ac3235d24b17e44508791f32e472367c209a4e01b2a9b430f5e10f1e), uint256(0x01ac72c080b349254aba5cb1eef07b39b061c967ab23ede5b97d3b2935432010));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x026ab792efeeaac6594f438474a529f5c99ff3f41f4fba06a2845ae0611175eb), uint256(0x02670061fc4cea25b94e34eeea1c086d74b32dd7769a06325f75156ef098cbd9));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x297f582f1b7efb2bfe56418ab69936c4c2174bce588d48c32836620f5647176c), uint256(0x268ef0ba5b0b54fc0d03f9e72bdaf301b5db04de95cd2eb051127c0ae5ae6ed3));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x098ae199e6df5619066651048b6df03c5538fe3c3edf27e9e817ae4c3aa82b33), uint256(0x04b9462fef1ae4e63842674782f671c5c8494e27973146ba645a693495c0b181));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x25f8f2d3a6e17aabeb029d74d0a4bc0a2da9503b2773e7503243f5968f03d41e), uint256(0x104514af9be65507811866a4e0d3dbf358f182026a9205d403c3dcef3a3d06e5));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x28795ab79aef3ed9de7ecba454e7b26f13c297cf2a6de48ed2d4c8625707c9c2), uint256(0x22239eb994bdbf7e21498d085eefa82dc22bf948318a54cd82a13bd1a4ef76f6));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x082c00e27554a2d77a9333bb542318b390c08b81544ace0d4b16d8e38d29fab5), uint256(0x1c63aa855ca22de79741031e163e6dc850addc485964b038feb69f3eb0c9430c));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x07e6a100c6523e251bd065779b3ee0867518ba4ed283e5dbe9db3734af476a34), uint256(0x171d7855aeec7a0a13aefeb7c027bcb1733de73ce2708456b89177de5e47dfe5));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x1a857a425f8ec92f872ff82163b6f4884dc1f5b80dd4693528d4fbce3b776abc), uint256(0x185c09658791980ae88dd95a0f932938191890baf040d402c8cddebeaec048f4));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1b30b31da46d22edb827a476fe48e87a2a0f212b752783790f8d4fa80bc5bc6f), uint256(0x2e3fda9cfd13c2e81638021048d2df1572b25aadd03bfab3cb425e3982773f1b));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x05b920434b81d5e8a904476a36ee5e7bea55fae48a5689e054542515ec38fe5f), uint256(0x2076b38419b83fce5e739c13feb832fca1b858cd672fc6757f6739a9158fccd5));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1a4a9664213d26b949599c188d59ff56c006d9ec870e2c3e8b60a0477a2e9a7d), uint256(0x0d89c54968bab49499e0d4b1ea2af3602f2bfe0a7d3508eabba65da9b3c16494));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x0804222579c3cc899162c6fc540cde9df9b61f3922790fb7c7fd2470402b1f22), uint256(0x07fbb119333b6770a8c370523c23151a17d4e1bd8c58638008b895d853291d52));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x04efec545dbb9144dccded83583e8b4f07ee4ecba34da130c2fb600aee601d3b), uint256(0x0157df9c38757de142ecb56c3721a97ce3adf768d745ff89a1f6e0383c52300e));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2dbd85af8d0ff7e2c43758ebb2d98823074a7bb75d307f621639a2435cafff45), uint256(0x00f9900cd06cf3a7bf36076adc916c62bce4a987d406549baa7d171262429c38));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x125667c9331f7262ce12dacd70b3e3ac172cab65988f11f718654cd947362b9a), uint256(0x2aafe9f0f75d68db66072e517cca0db3b71842b291d00a4236e5829f9492dc8d));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x1381b201b5d6d8e2d0159f607bdd1984c30fbe75227887118d656518ed08337d), uint256(0x1990827c7323f653cf1e281cfb852bd6501ba4e01da25519413174471897987b));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x18c42140386439b001aef4f025eafcf6b351d1aeb59515eedd9d9f7e900acee8), uint256(0x09d6bf66ef61a4fc7c7c6b03659f7d02f1cd731dd6add0af1a719d6dacbaf669));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x04f71e82219459f0771fe4b31bc6906a9e2a6b898e33b76a0e8ac89cebc0e267), uint256(0x2f907ad922d3ef8a58ad77e38efe71766be96e3b03d2e290454aa7fa49a9ae24));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x23ba55853d8597f5183d386832ec67d11cc027c65e1de23cb2fa95b53127ff33), uint256(0x10314d893e0e43439b879863f60a05ab2024379235d85cfc34bd0c045413cbc9));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x046115f8edf12b56ab3b2baf05573df57c18a14d75768a3a83722ecb9c9f3b61), uint256(0x26f0adfb6e43b68b942904aedaa3d383f95ca47da13d2806abd3915d4e58e8e9));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x0d28d6774852638767ec9d52630253101578ef81f43a30db9a492881a58449fc), uint256(0x06d46816a3567520368139b77cb03bd9a602afdf3c24bcff5f485d0ab9d025b2));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x1b70a9b0fb489285ad3f3111c184be5e8907d84b75bbe3943405b33fa930a847), uint256(0x1fbc0016018f21019cf2b4e610b91b4a7def2297fd950512cc9f676626ce63f3));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x1048817108c5711276e56cfe8fa8ffc71e464d00477ff33ed1bea0674f9229f6), uint256(0x1bd5fb512e4ceaaa3432b3c56207463207cd790da85a120a5562f388a1a0a14a));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x03b65ac2174113707a7fac5aadcc3b2eedd5ad577236f7504478fb4f37241c0d), uint256(0x2894d9e57db784d7c199a7bd795016413ed6611f325b8362846e55057275b93e));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x13903e580621621d3407165369feb74f2b159a0f9ee773396f710eda1fc367a6), uint256(0x0906be35f98595f28c019b7e1264094e91863e41b13a5afd8cb7db419daffdd9));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x29048befe052e6cd839e17bdd987185fa316bff296803fee78b26dedc7b60e69), uint256(0x158ae00fd89b7c8ccff00572260c82bf0f03c12751b92c8848c49d9b4cb32a11));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x228c296b7824339fbd8fd6e78c20950233def380a3845951d442049db26e6fec), uint256(0x2017bd6471e6ddc1c738c76b28cb7f33d2a32a88296316fe131bc86043953be2));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x01a13010f3fbbbe00ea30503fc69aa806e46261d9484678fc182a9ec4d4cbab7), uint256(0x11b8330bf1b66a7abee2ddc9d7d4a112a3d9044198ba2d75f2ddd4969d9d620d));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x0e7f838ccf62bd2401cd0d0810f2e454b227278ed1f463b008c4f2fd202de80f), uint256(0x25d6be103ca47a7069fdb6748a5cec031245629561dddcb1c174bff1bfa2c348));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x2354b36b16324a2b0f3c28319438c99c6e748c000361ec837c4ac21c222889e2), uint256(0x1a7c30da24560967b6ba8397c8d8e78689db6e5adcbb17e5d95b980d1be4c6e9));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x255b3247baa4bbc90c4c8fb0a548bfae700ca126ec6d8daf301ca9d7dbd95c28), uint256(0x2a057afc4589871c186762f69f9494e0c6e2828a8a4519230ae3fc99c4ee16b2));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x19bd952e5341fa97ebfb9e49f51772c1b10272091d094084d03d34d65e456191), uint256(0x029bd60ac6c27563b7bc480805a085ec1f19642c1661e498ca49fa6f4979d65c));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0621482619ccfdbdd7231df7a951284d9e619080acb6a0cf0a01858248b5831a), uint256(0x01f30119b257348784fb015f85d833f3e12f777bb68f38293fcb410baaf5b859));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x2b1bf09fbc8d901e48079c34476f4fe7264af78991efd95ef52c85c59ac60b02), uint256(0x1932f46521a6dbdcf366c2187442b848374489522713cfe27e4d17109c631e3f));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x230f23920af89edf284fe1203dfb8904fee066dfa2677f50106602bb08fbe904), uint256(0x13a329e820867cc359e4ba9b26a48c861d08c36450ce3b74dbdd1c09ca64222f));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x082a2dddf070f6b476e5ba440ff23c5f8f3629562f10c44cfa1bc42f3baefa20), uint256(0x2f7cc69e6e6ef6285c42df0e3d1844594e353d94f3911709853747ba169f7fd8));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x2aebb98f6058e7dc37d474194e593e3091522aa8de2b0342dffea8a2c67627f4), uint256(0x0068ac8be6171847846e0492238b93a74612c9398598f23999731614f572f891));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x04b61b00c440a71f8e2dcbfba7989430b487966d93bcca53d0025fe9ee435674), uint256(0x2d516f2cdd3db6c1dcea79818a856a055c723084082fecb277fae49b347a2a65));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x0a6849e6096d6e715a277c7fafbd330e59f4183ca30c663bbc734a2da55944dd), uint256(0x11d0ff2ad452b5fc1ef2b3dc67adef8621f6b3f0acf0632ec4734c17e4773605));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0cb949c2032e78699ff28d18f8b2fdc24b4a7de93546250f870f968dc375ecf1), uint256(0x11a9f2016211a0baa71650e0afa810f51f9be86965c739bdae09f22f845fe408));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x0ff2bb3da5ece01ab9534d5c0234442031888826b9c0076d425c601ac816bb8d), uint256(0x10814e094d9ad93f8dd2617c3de2a87bdce3820547b706f6caff5e303b094dc5));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x008b64286888e0868cb85de147504e3003ca1c2e4217f563da0efd356b2accd1), uint256(0x04f131cb027e7ce0f4fbe3a9485b726e32214ba104cb8a67c3344a555608188d));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x0df41180b75095addb52379c670aa9319c58d31321fedbdf5a2155f1b30a16ab), uint256(0x1d93d13b9715416907ac25c3bca9c4e479e0f6682503e890d9d79bb296e821cc));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x158f85b6053aa4d5bc4587dbcc5715a56be318d3103f6bad662fa9fd1e2df1ae), uint256(0x0d55b000f44c6fc7024b46f8a419cb065ea174b222681a0dd132e560e95feef6));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x1254dcb0e424d45ab3f0de91d55a27404ede4a5e5f40e74d539696d64f0ee8a6), uint256(0x069ef65273652c91d15f05aeb4a810b7c413511a6034aa0d4918920e5cd9a4b2));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x157c12956f00337cc80adefb50f34a8383fb223ae38a5993d11b3886726dd0d3), uint256(0x1d9eec01853533b2c23ff00c85df2a5d1b6bbd435b124bbc2f661936a3565c2f));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x2782e856811cd55f5ed25622ff56e1785bcf2e322ccb5a8356819c264712ebd0), uint256(0x303576cb8ccbf2ba314f13402d3f9eb858333d56fe21163d2f1b87fe939f01e6));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x0d8e67150f819d1f130a8d660ef5b1c6f8651b4e5fb0fc3c011ff87bc6c64f97), uint256(0x279dd75ee99a97aab38a23de6b3666c5f5007765462dd78705ca00223abf1ef1));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x09a831b0dba7062bf0c9b917bc169efc1ba45ab3fd46e84e0766642631ae7662), uint256(0x222160ebbea133320f6dd6735605254812734ba649ae47a5bbf90abf8520cc42));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x0bdb356193e99529e59c698e2fb7f4a5b3371131acf8037a3ba82bb20ebe0f02), uint256(0x1c98b6e5749f56b8a5e18097322129381cd3f56e8a06c3917f3fc9d73ab611ca));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x0da8760389cf42e1c78ebbaa95dc63ea945c486d4cd398fa151c074bbb1eb473), uint256(0x0f6b91797069617e9996b143dfee70d2fff557db070585d6f998d9012bc441a2));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x10047515839a859f44c41f7082c0777c319fd3f930df2ae944e37a2b4f42b6d1), uint256(0x114ce37447a2601cf77bbe51332ff912f91a7aa32140ed214a2f5a90e8bc4564));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x2366b7fa66dfe726ca7f791758bad1abaad565441bd6d914cd0d9889f3fc19db), uint256(0x28a125fbf4971e081c8d3b7060f514793765db95b7fb652ec3df843a0affe5ff));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x2e9a2e5f19f955be894a86645185cfb3a2465c8e0047ad4b03834c0ac94d7295), uint256(0x00e690b5620b3c6d3f6125ffed8d17e16591bb418521b05bd1637607fc65cb7a));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x254f28bbbe65119552394a89265362f20b85f6037045120dbd5360abee34cf98), uint256(0x091b6b4319f2f78e37a7f1256b24dd06f6abaa5bb4152e358f99e8fbf6d1787c));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x2976fe3f5452f91dea5acfef1681575d763493937e1134bfbb9f0570ad971e3a), uint256(0x1084876340dfd89c0eccff715ce2355cfd46a928ec1c544d087c9f67a11fd314));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x17f92997174b2e118c521535430e68936a247e38fa616997ec531cf5f6026ea0), uint256(0x2520af9d270679c585b71e75760d6ac39dad5516dd0bb0a58275e259d7de7617));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x140863c88003999755da0988837474c28e4378000d919733147dcac9fbd711be), uint256(0x2ee67a0c4ebe797360baeb1e88ed9f28d88f460e9c8ca83b1e57fdd5cd4fec97));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x2e0e4d78a0468efbf27f5be88b21c1578abd8108f60ac17b87835849d8b3d851), uint256(0x1b265b8b605608ed73f5f2ea43d60f056a8c2e1f7b03168df7c98b96755a1386));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x26fdf6daa0187e5aa0a0b5ec3f28e69bfd530ee590ee26be160519955addfafb), uint256(0x0dbba96c29dc70f492aebe09313d0ff72b38d7d50c6323a9e410a3c5edfd0f64));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x09ff88a3167ea8fced270d978104fc31217f05dc4ac8f02153785f3a4c836be2), uint256(0x2168bb543379306d3811e2aa7156b28af059799b61d2a933908b4d0f84e5dfc7));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x014280114e725c9195c0de53eed69a923519a5fa37726d3b8234d872b23fba80), uint256(0x25c6585008e0f130a7e87756f532ef5e5e392e35e489d2657232b8de996109d4));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x2426f13413220e028175a92e61988133974527291e2d9d06d3fbf993545c583a), uint256(0x0519f675fc733b435a4e81a04c6421f319bc6a29ee0013df6bcace274b977390));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x01408d9649e24fc1c1475ae07847a6d481d2ed60f93ad2e07180c99ca361d9c9), uint256(0x21ee0994a5fe053b7f8b96d913ed21c5de6ac6b619fcb1cbef94a3db194a987c));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x12ca6196887221e6876e5056566be520b3b60dbe431564fa41c7c4496b1d5624), uint256(0x17eee2658de91d05c0d777b092933e58d394ccb2f43056e55f4cf7225432eed7));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x0258b9bc40b6dd73ed71d51c0aa3069483d272bf1746f521fd4ec1fb7de59b90), uint256(0x245d726984b0429cd835de1cfe8993df0a1647d1c7af979b34c084ffcaa07b6a));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x16c427ce06b0bafaa079c8c1d27a50fcbb71ff2fc0db286f9837110a60a927ee), uint256(0x2bb3ed43ff7d3e769aa09bb32fb09a1587b3d73fb945c702f8dbcc9da2346e8e));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x2eff739c2560f7c797dfd3a1e188138522a996333c1acd6744cea14b80350477), uint256(0x0e682d1693f33a2988d85f8804fd55d11edf9b8595b8930a724ad549ddffca63));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x1f861a2a375f7945f274ac081b74214a9843ef35d8d38752145b53001d084c8e), uint256(0x21122b3f13471f2fe2a2791580e3d7d42b288c47ee2d977d6eb5df1033793ce1));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x2641514a377daa4cacc688911033b1582da84914c6d757ef4a2800942dff76a9), uint256(0x0b7580c0e7a331476f5264c4f1da293fde08724af036a2c4fa3391d4c841a6d2));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x2e3a201466e9a66b3cb2ec4d97060ded675bc3355ba84f6bf4fe64dc8fbf7b2b), uint256(0x0e88ab237d277be26f7847b4e6ba89a178e4419e9d9d44420b392dc50baf0fc2));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x25eae7103a3c9801f07fcc52750f83963c4718ad7dce7538f4362f670d4ecf8f), uint256(0x1ae929bc88b380aed507a17f9f34d48dd6da51ddb3a3649639b01d0d47fbc4aa));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0455267f5cabbca4b8c1fe286ea9508e3920a12b332a74502e4df67850ecad96), uint256(0x2d0c7cf0fa2c8087db30931b96cad33541c59f18dc9d62e888869746a79e631a));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x264fc03056fd5e3f369a49c3a08cb21ca6c0556366190554f059a6facc945f9d), uint256(0x1fcaf3af0bc493373e01bd298bdf7efd35987bd433ce8decdc1f35b7029f6f5e));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x18151a1796ec615c4725eb5aac9486de774751584f779f656fa89b514cf9501a), uint256(0x206385c996bd3ada499cf1f789ae774dd81330352c41b9aa4a0a4565c5b1c870));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x28ba58d78131677bd77beac64cd6f8208333c5fae02fd0d369cf4e1bc1d3745c), uint256(0x2a223c28c4299fdf14e326daa1f0c13783715d15d4d6f3e85bc9e6c8f1a9b292));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x19272d1d0d610c3c7008bdacef7fb89104624ede9201d271253ced434dacc511), uint256(0x1dfe653dcd2224b6f48d3c15c1af9641de8b0c9039e2331db44576ea7a346b61));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x1c155f25bbf19e4c31a83107575edd54b39cac5856c001ce3c5a28c72df2f541), uint256(0x0a8365cfd531628f246b835eb4977ba3a1936c367c9a792f46b0c8c05fd14290));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x1aca5b625c33d8a22316cf998e3c50adb3952d6105b021c1e1dbd3205a21be88), uint256(0x076a4791d2d051694a48d43e6e81df8eb92b88e52af49f19dd65b8ef29863eb8));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x134d2cd984c1edb0a43bf003723d5a1e7b76735c47c669ddf3580cb45c8586e8), uint256(0x06ddc40965e1dfe31424ba80aad3e52ba7afe2935abbf389672191f3b905b788));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0666066ef4a6e334e8d0eef3ebb86bf7b19feca3e06cf315d1db1923f4550980), uint256(0x0e1ad8cef00f2c26e9f8eff8e19ad69ae5e29da2e09fb4f54491cb1bf29988ad));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x2f43a831e71c39cf817c64bf2ac5da6f3351e04cad22969b0796b4497fed6eda), uint256(0x0435202fd47a41f19860f2a5e14754ffe47c703c645cbfc44ff679098806be37));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x1a429eee40890befdb3359411e7c9d1c6133619b9698b85d0145f993da0ede33), uint256(0x048994744be313ea050ab2def0f6b14d7d34fc106b0d5eab5bb102e4ad936f93));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x0442632b31e679a20d7cf9571d9defe65620f462e6ad84062c784d025af80822), uint256(0x06f1b0b23e0be0730c6fb9cdfca52dbc6a3b2fd95a728e0dae42e3736086e05e));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x0d23ff7c77dee1c92ea57e0314f8a51f781647f0f1243b7b772e8b7b0276420f), uint256(0x12d6b0eb9f15784bf153e0af244ade671688acb9149a97ffcf73bbc24505d522));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x1eae274c27352d3d120ee774b64b199ca9b9071236bf5fb907d22f619857d822), uint256(0x25cfdae218a5e0686c36424dbfa68a6a43cf2475ccd17715c50a935c045eae3e));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x0c1db18bc5ddd18e108a212b7f59b7472ae521090bc15cbeaf19eb621cb67289), uint256(0x2613c732217059620f5c48ca7ec3af926b6192fea893869ba26a7155c3a17a34));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x23457f6f21dbe2456de7f13be29d3ce695f90d63e09a2b9d0ed03b875eee6382), uint256(0x265ac3ee3d5feb7ba198c2284bf609a448820b7363c6be097667b49a8869151b));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x2541cb6d57d7ef9dcfe3b4ad83fc88dc398267b4e2bb403214ea58e65be8ea2a), uint256(0x10575349719691e8577102af7c2531a64146ab4ea958d0262a2cda1e2f299bec));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x22c63c47d51fc40c4c317eae7db246f8519e5f52841d5cbf42bcd74fae2b936c), uint256(0x1996edff030ce610bd8b324b8a53239540b9ca656ea66601bef5fe61a59517da));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x107da9929798bec551097bb634cf281854b1301f8520b728a1fde9342c4bf79c), uint256(0x235358230ea6d3fe28a582bf8683ff168f59a58f7de6a0a00c9236026b8b0f71));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x2eb41154123a019a27be41f106e2cef4c8d14740bd264f1002b79ac92472f1ac), uint256(0x2c0a3b30aca9d6431180ee1a02acf3674713fa16213644488c5c7060bff7d5c9));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x1bbaf85be6ee5f93bdd04aea57014ffdaa7a8ec87171b40b20a3978767d978e4), uint256(0x16df0994316c1456fd7526777b2e9f992a6cfe1605415d1b905809613c7ddda7));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x2cbbf5355ebd8c0c94c7aa0cf191aef226dc7885c375dc0966c09f3c8729f7ab), uint256(0x12fc933c6e345c54e5f4616cb975877810ef0d1275fdcbb3be16013a511d5935));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x2b84e97745f4138d3df32695c0883bde145d3571540b80e00a88860d24a63b78), uint256(0x19f2a43cd2d89d91c09f4a1867f48f0f9a22308c7700557648fc58ccefcb5445));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x1d4bf8e5394627c769d33a773c98fb944d4b9127b37a91a6099db2bce2dd7a4b), uint256(0x0d248ff6a459b8a2d8dd7c087ad3cc6d0ae0719a5f73e223e916231665a085df));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x222995472ebd06ed7a41944d7a05575cc1aefd1d029102c7c44b9c2b15c348a6), uint256(0x2478e7dfda9bf3cf1d498fe11bd777bae22682be84b342cb55e913e83f7156d2));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x2b1ab6931f701221453a2e9c3902387266bd0555e6af1ae44b81bbd2e32ec29b), uint256(0x13bff4ede0d12f1edcb242a86d79f7c8a473c3cdcf7dfdcfc9003f4c892203ce));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x1b398dd4dd0beaf98169ceb59a3f5e572d39ebf0f7992881918eb7e61900794c), uint256(0x249ef0e3aa4687e9dbe30fa951e16114c3d8518cbe3ea5eab2b820d87d243e78));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x1e1e735a42191698b228add28ac5f6f866350821c984e40b02f7068fa08c2e95), uint256(0x244212f189b47b069bb618deab199da6c61432bf16720c879652cb7c8bf81651));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x2ae0365c36559e347d9b63dc50c46fea4d85d3056415e0133f39d8ab30284a5c), uint256(0x051bcdb103b58909ab9d2cb3456b2a124c43450d919455436938a33133642dcc));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x1b2457974641cf586c9cea71c43ea08384dbddd487f1c20d9512f9a166b4b083), uint256(0x1ca41251be18d8507e7963972295adbab6d8e9b9746048cb198e74ee20846a39));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x0ca91c8640de4f19fdf051dc5cfbab32a7ca2b1e6da07387afb7700a226e10fe), uint256(0x13d4f3de16d5130227cfa81028e1ce434619689f58388d956c5da37e16678dc5));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x19f964ce99ab4e435b79510247f6ac88d0e8e73a3da0cd97dd2580e2e63af9fe), uint256(0x138d4b474beca32da6c4cecd90df789a29e261473fcb28b9d7e6dc176455216d));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x04f8dd089345ce4ceec3734f98d5043b6a5fabe892e32b0bece682f03652c717), uint256(0x2da2de899da54f9f06c6d7565f82bab80bf8556e3ce89b1784fe81c5166a1884));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x107346ad255811b25844bdf03bf615585d5c0cdc768fc7bfd66fba15b972597f), uint256(0x19bce03ce664cb89c7acebe95e3a62595bf0972fa2a87fa836831e496890b8c0));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x13f69cfb6808c8427167d6670fd5d4204ff1662132c6a7044054a6c2c3bae242), uint256(0x028095f1564a30f65734b55144552f1b94959c503a2c56606bbfa13874d60655));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x2b3dfa3e0192be393faa0b7ca7b338652753946aaa960db55b8b355eb7ad6c93), uint256(0x2555bff0f3c4b45a5bc6dcf12c7417a0fffa8f63e8faac95ccd14f3fe7c5514f));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x25db182080351fefbf69ee6df1bfdb3160559503ae5371331dfa100dcf4fe542), uint256(0x04eb463003e8449199380d9bfce16fc4ea68221e55312921fb6016e5a6d14b7c));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x1dee604ba751b97ee477c40e5480ce1245a682838ab985623128836eb13e0389), uint256(0x11ab3971d4dacb655d6d635b9f8f2af44438c774a819bb446101dd23a8ba8940));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x12c3929e8b688689e75dc1c7e6da6525d757e8af3f1c604ec9960c3a2a5a2f6b), uint256(0x11647ebf90aeb10ade8805f303e1b3d631ffc3eda77d97d8634afce2d1637172));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x247e3bef70bcc5def751e1042706ed08783bf9985847041653bc7e94e9988498), uint256(0x1eb956bbfac26abe2d4c77a7ad08dea150898a8da3ac7da6373576da8d71f9c8));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x0823fe07b0b8b9738776aa2cc97ba6fa5cedba78a875c2217a563e5cf794c56b), uint256(0x13f34db8e74f8b81479910b2cccc583e4993cadcd38483bf2697dcb949212725));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2aaeeb8974502ce9eae79337214df5624fbb60df704263174706eb3effac7b68), uint256(0x08c28486f0221e042bd351f03fda3d5da5c953a323f96b59df0550235994a29f));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x0515e42c243955c5ddc046643dd7ddcd474f22f50a74afcab2c153c5bbde1e81), uint256(0x14be8c1863fec1cc39bfbd25d6c1a433a97a084c14377604e1fa91f2b6774aec));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x0e2d508eddeaf0b075dbc20ac22976bda97ac0dbd52777e18e8b10df1281a320), uint256(0x0af8456cf3c71edc6797aa52274978642ade8a83087c487b56eedeff56e9503f));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x1cb19822485bd015e2e9c84f0aacf3ff527fb2a47c576c186d88798ba14b6033), uint256(0x01723191d8282566bc52fa42caa9d50d115d9e4247b3b9dbae3e63356c21e177));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x14f10ebb93de42274225b3d4a18bdfcb430a1cbfdbdf7ec83db094caaa5d5cd0), uint256(0x1742d1b5014dce6e10cc1b9deff147a37fb5262a2407645f053d780d00cbd7bb));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x0e80a0f006f3bd326210e0f96df654a37a721fd4f41e8923789bf75f39748aab), uint256(0x01021d0f6c906f2b1db1d21d5115debc5a7801f39b0515fb61a4ff5c448d588e));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x1a7af4cbc2eed473baaea22990a108ef2407988547130f94562df238e082f020), uint256(0x2af9d0a10a16ee5843aeaa838913950cbdbf6eb9926be66fd48c90ae3d9b59db));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x1eb26e632002d56be2985ddc768271d97ac217da5ee7ee0bc873f745a6ba34b0), uint256(0x0f615fe2a2f869eb9f962c4822000ee641797efa55fa15628e7fc36bd87dc1d7));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x15d0919dbd761270b25e274b6dc460b62d70e2ef918b45dbeb99f30757dec77a), uint256(0x0ca3079313bcf73c061aaf093a17405013acc6dc6fe02904f21a2e8168bfb73f));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x0f7342901f32266f36b8d416a3d250e34d57fc24c58c84c39384bb170d4df74f), uint256(0x20331864a515deafdebee9a131b04dbc15a330b31072999b9856e01a1b37b7fd));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x0839cb350e39769732b9be8556967550a63d68eb8d6755847fd1d6eab0eba53d), uint256(0x25db02559b23d095522e3f332b9ee1babca98b493b160354c745c90d48c43210));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x026dc9f6fec2d780fe0a82ad949caa0b54ddd33045e72371f19068188b2af770), uint256(0x14875ebfb89523b8eb5270f351de97a30fb6d9f868b8d6519336de552d142619));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x01a0b526ebb70040c36c378d1ab0c8c4da5159e8269daf990856c88d72fa54dd), uint256(0x1cba40a577c145a172a982068fd45df4dae638b1e01e2670aa0ca549da109efd));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x0e30583421f4131382009de930901ad2c0710b23a3e4f7ffe62b54fcc3ba3660), uint256(0x0292bfa3fea7a08b22a268df46865f2ca98f83d355fb73592c043700c1aa55ba));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x2aeec657d4d7469fbfad9b6c2f97aaf0e384310637ea6e9946db4223707edf66), uint256(0x0f441a21b14ba927ef25b25b593858f8e3e45252f6720beae6adbf42d54efea3));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x130eb9e5d3d37f81e7616bc4b23043d07f4bbe568700c6cd9caaf7a0bbfe73d9), uint256(0x20d68c396d741df2d4c122377a13935160d4dc7304c8d3db1ee0f2241f9a15f6));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x1e518126380e8ad9bf1356bda54c5785140aa49d30b4581d39e18f5c672bad5c), uint256(0x205609d56e90fcf0d735570df187a847f4beca37753ca225c4c719adeb49665e));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x0b4c5b9e6c29e4e02104ab6d69a98024082c14051ba486bfa2e0d1b6a55354b3), uint256(0x2527f3124aa9ae2c0d4a11817e48bc3db69090aa6e01c99e6f8064aec149f313));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x1b91cc0c7800915487ee17693f0df01ba23ca31973494b5e1cb7ce1126b85d28), uint256(0x22c08e481ae96eb003d690c909080dc570e369df3d4c6e69183ca180969391bf));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x07204248120e8a8a23074a47425d6d1f91bfb428cf7b7a132e199768a1cb495c), uint256(0x13a19e01b52dd47cedb725b3367fffe2327977db74ec4e5371bd0e0967e4ae48));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x043f726b4e5e358cdb5736badad5b7ebc2838d85d2193be3acba5e9e954bd677), uint256(0x1514aac6f4660554b1717a1d5a4db8b543efdcf0b7138c0b6c86733ddf4e9e03));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x29b21acc36cfa018807367ba2cc005407ede42dedf7c8b0752f4545e3dc43cd9), uint256(0x0d4d7ffc9074a60d7eee9eb8bc84b8a20ee30f21cb5740b1fd072c7787a1134d));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x120502c183cea50dccbc884986d5abc610e8c5ef774fb1ae6db38a43fa0feeb9), uint256(0x04580b6b8204022233f7bc017fabb6303df4cea7c42d82700a795ca4ec8a6d48));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x042b629adddc915be706a132411e60be77ef123f639ad9ed22317aec24976f5e), uint256(0x1c271d91cf083ba21ad190b3686093f659c205645228a862b465d6e232514d2e));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x02f271f6d62cb42c208b4524de9857371e8da29512ad0bfbc69f973a27f378e2), uint256(0x14f687597252e65a1606dbad4f7308195a8081b56523a3540494f1a9381b8fb6));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x3017b37a49a146fa0cf3f2cd252d5d7489750567df85e6e8c2db98408c3ea969), uint256(0x08c304e35e5f4c92470dcd7c462bb5197ad7ec6efc2173def97410a76e99366a));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x042e08d9da3d369990c2eba3bdbc572acaafe247553c82828c93709807a1be2d), uint256(0x17bef70ce5c6bab8ebdf69cd0ac1f766151317d72d3bc3a7b17f2d1bcd106802));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x016cb4b8ca611a05a213c80e826e094575207177f107ed756cdaba9c14b64288), uint256(0x2240812b8bd0577ffa6dec3885adf46ec2e4caf14a5143d56b6bc18bcfc54ef7));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x27fbc6e4cecf48cdcd346c89359d990f66e8b6ddd39c7c17011d0dc6557a496c), uint256(0x078329c4b2d84560951d02086f8157a3386d16ac4e4d4a93f18521d66e1fe630));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x091678652ff10dbb17def2906619aa044e32b7f0142ab466f6e09344edfb4ef6), uint256(0x2dce2522a7799c99f1d033db3d5516e8f8e65e20913b64fb2a0337e65be2b753));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x1f94ed48cc5b1d670aea5f2db4f34a24bfcccf691428aa22a92fb6e1d2ce318c), uint256(0x076888b07b03f84233d02fe6dec7cc97e9214551225dd287be6616b4b9de2f3e));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x2ffd248137b0142bdda45c8f86bb14ea86c66371bc8933c3341489c867291a4d), uint256(0x07ffd1696cee68d4c550306dde3625f76160098eea61dcc0fe6e029056331de2));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x03e21b2db386bb9eb3ff18101fc943e78d05be11be6f1fd0f66634e9be0aed4d), uint256(0x2e3cf5c9a439f8118ad20d783b0bc77f348f811c65e70263bad5e4db6df73334));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x071da71f028cf8f4edb5ad62785be7fa7e93db8c571b359bf788193da92a4cee), uint256(0x03f898a9312ab6eb8e7e0f4d1d391c8cc7a85ba907e190f825e320a67f14bae4));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x2ff3bf46beb553cde3388a2888459b6361f594541e9de8f471181bc868791dde), uint256(0x2676931da15e0764eb5cb49eaec76c1e64b9d18bdfa239c8d68598709792a3cf));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x24e013f49e94859805da2d0d968f67e1899c879b202a1ee448d2474538eb1890), uint256(0x201852ee04b2cadabeb8d829600b0d4d60ef958942759d1daf79f491b195679e));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x064725c03543cce68fb098a84262d3bcd1729d52c897e9bf7435bbc671f8f716), uint256(0x2f3b1f4aa3cceb170ae7b257eb5f1d2f683ca30edda1e17b83dc96a2a4218bcb));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x16551c70e3da90f6b13392a5ea1c2633ca66278f99141a1ef7890cf93ea9d607), uint256(0x151e525ffa6cb122324dcba2784513df2439d2e8482209c6e2dd32a9a500c97e));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x1d7306c2b752e92ae3aa25782a4f39c1fd80bfac1c7f522ecd7471fa2b86ffee), uint256(0x1b560bf3043eeb3316a2259418191a3b06d56651a830b3c4f3100ce097cfc344));
        vk.gamma_abc[273] = Pairing.G1Point(uint256(0x17c81263d2e3a01cf2694d26f7048c0a7744cd888db389246ee0340a741de2b2), uint256(0x21c16a9618bb8c5358f2cefb46833c36ddb7ffe524892242323507f60c293f00));
        vk.gamma_abc[274] = Pairing.G1Point(uint256(0x2abfa71c1c416995b37d7e803f3f09726ee4204fff0ae978416b11f901137921), uint256(0x027132ed2a40878df89df2006abc362f785c42a6f4738ec83b037279b030b9f1));
        vk.gamma_abc[275] = Pairing.G1Point(uint256(0x1173608e75d589426892bf27eb1f7b693f618fe72121c1109bbf06b9c48c3ce6), uint256(0x01abd324cd7063424f35d4745b244021739a1c7778064fda2a2eeb67bf056d2c));
        vk.gamma_abc[276] = Pairing.G1Point(uint256(0x03da9d488a0d80e5d3b02100423869e60521bbbe51bfa365ac78d7dd3ef9a226), uint256(0x2d37edc9bc9ae82d18fbe08cc25e7615a5d805d8dc3a9ba1476f0de82f8091b8));
        vk.gamma_abc[277] = Pairing.G1Point(uint256(0x13043e70f104b64b126511e5ab8a3324be39ad2f4815fc46bb4bdcc04599bae4), uint256(0x00d734aa732c74d3247a155bb2585a7b4978d11f183dce85b2615903e8c309af));
        vk.gamma_abc[278] = Pairing.G1Point(uint256(0x102e892cd3144cc9b5f68709a2f99f8c8bc0b8a02ff82b5949a2fda93463ab30), uint256(0x266bdbf097b7525b1fa267bcbb18c1f2b2f6ee7749d6f771e0f44eaaf744a161));
        vk.gamma_abc[279] = Pairing.G1Point(uint256(0x11fa60db71e09fba74cc3af2c5caf37974d9134da77130158e46534e996502e9), uint256(0x08f87e02e3ecbdb8018da9f3fbdae0b3c3d8907da7dfada216a0f53fb6b2d318));
        vk.gamma_abc[280] = Pairing.G1Point(uint256(0x2c0737b5e614ce744592306658b9a6186d515c241bd654c87566f9e97f926508), uint256(0x236f198ba03a5b1b7a7da6102042f200856b33601928afc24974540433b07c3b));
        vk.gamma_abc[281] = Pairing.G1Point(uint256(0x2fd04798465340ca7761c3ac15cd21b15cf0f3337822d1fb0eca722a88a352ef), uint256(0x2983a58dffe58b818afcd91d5a7ff7654cc2776d8d45fcf42aeaf72589bea3b0));
        vk.gamma_abc[282] = Pairing.G1Point(uint256(0x295892dac4b0c1ecc273ff8f93da5eee2ae4abce4cfe614793fab65cb9c6b4b4), uint256(0x1c8b91b746e427ce4b7f2020d567fb23c8c8dd80a02d7f498cb816d1dbb3cde1));
        vk.gamma_abc[283] = Pairing.G1Point(uint256(0x0a3abc26e0a9e03031ca37e1c997f978abb88f72d34624c668c340b63d9884f0), uint256(0x069b4243400fab3b1442fced8d18895c76a9240c532fdcbcd0d83f9b371adeba));
        vk.gamma_abc[284] = Pairing.G1Point(uint256(0x071e14b44e63cf217d9ea51136153f1ad026ba61f122f593c8ae03f7d7480f34), uint256(0x21a0bf70d1d14ec42483681cddf2b2d72bbcccb10e1ea04b7b4c99c83ee61282));
        vk.gamma_abc[285] = Pairing.G1Point(uint256(0x132570670e46790c17ce6a1d5d3f889b4a6d03896d7a0693b6dc6291e8fbb617), uint256(0x2e088c3254363c56ea8738781963be39e6759e27b7f9227571330128eed9e6b1));
        vk.gamma_abc[286] = Pairing.G1Point(uint256(0x114c2d743915970791b1fc427cff04b676d97c5f21a1d55e8d4ed26bae5deeef), uint256(0x2e58503829381ddce9b4093ed66ac0b16bb8631ad0797ea287f40ca26fb46039));
        vk.gamma_abc[287] = Pairing.G1Point(uint256(0x0a17f3c97257be8b5e48d937f3d6fab21b184da85247f4d625fe26f449b1effd), uint256(0x0b74299671d0c6a27a9f2f79c3781b6b982ccacf23bf88f7d58765d04449b397));
        vk.gamma_abc[288] = Pairing.G1Point(uint256(0x0881358f0cf64f04a410e0ac3d6972273354131750c42877271b012bdd4b014e), uint256(0x0e2d1d771e68aaf15c377ad9ac256dc4548020bbc9b8b11cd0b8e162982f6b57));
        vk.gamma_abc[289] = Pairing.G1Point(uint256(0x1f2e3d49a380871f0885cab6dfaf6247a8998720676e4b738b9897028db43349), uint256(0x2b03334fcda9b16574fa2b0bafc7bddb05150106f5c8aa2e02899ed60c446797));
        vk.gamma_abc[290] = Pairing.G1Point(uint256(0x1c7b34b0fcccf7943f23e17fe220e238b4e06e907ef90c53ab57fa1760b8cd3c), uint256(0x1d9343e40f3acb0510889bf71ee0b219386fcd1f70001a6986c2cd01f737f4b0));
        vk.gamma_abc[291] = Pairing.G1Point(uint256(0x03c2a4f281d22a25e09f180c9f9c959ffc2920dcd7ed91fdeafc3df748cc7710), uint256(0x0358f88e74b98d35141cec3e02c3aa11e961a81ef25ffe2060a3cc0426da2ec1));
        vk.gamma_abc[292] = Pairing.G1Point(uint256(0x00e085260f9517f5ca8a1453cfd960c3cb10c8b17db5e9f02095d8148e10a693), uint256(0x1e6c1559ce9f43c5dc0712e985974bddab26c42e763e5af4b4916464002b283c));
        vk.gamma_abc[293] = Pairing.G1Point(uint256(0x02112387d440025cb021892b51be0e8262fc3c5e8c2ee9909ce46cd9e577e8d5), uint256(0x066fe2da699eda148436a0c1c3137b726a9dae392b99cbd0d91369603439d94c));
        vk.gamma_abc[294] = Pairing.G1Point(uint256(0x1fc2b08eb63cae9f7183dd7a8df1b2219944d15eed60949cc3633d62b1cb5bd0), uint256(0x08f7b8388e074abe33ea7e5232ea5533a0671c1c497b93c865bc4fcb7b7e9a85));
        vk.gamma_abc[295] = Pairing.G1Point(uint256(0x1dd138ac5676aec527d81744179ea1b5a4e0e96dbdd972f468ab1896ef2d50fa), uint256(0x1da123f08b31ca3268f02553eb6f71ff9dd5a9b9dc2796c0e0973a82fec9c898));
        vk.gamma_abc[296] = Pairing.G1Point(uint256(0x1238370b6bc27be0e7ccdae70956db657d1dce19fa6ffcbcba4ccad1403467c8), uint256(0x29be021c03bf3f37e3b4cfa4b4cbf61c0c64449cc03affa4af691a84efcdde46));
        vk.gamma_abc[297] = Pairing.G1Point(uint256(0x1b018ec9f9cbca81bd86882cf6578ea6d05bc03a501bc4a833fa0fefef8e3b32), uint256(0x0bde9f7a688574bd3466cffc864f04f93536168cc773684ebbf0a6cef252a80a));
        vk.gamma_abc[298] = Pairing.G1Point(uint256(0x178f3bba30e3fb0e2dd482c05a65e5a39658a335cb801a94a11ea642d7a9d4b3), uint256(0x039d58be951f811ba2f7eeba54957501fdcfeea4291ef52ff88fba384dfb5148));
        vk.gamma_abc[299] = Pairing.G1Point(uint256(0x0669519de992d89bbe275f99da2ebe0f2239029e3d1ca25403b56ffe8bb7acf6), uint256(0x249187876a7e6cea669a9f95c88dfb56a5a39fdbeb82e094043c8a6ab08238b9));
        vk.gamma_abc[300] = Pairing.G1Point(uint256(0x0880d7679168e048a50bcce13bde492a35d0631e9ca934d2cf43dfa9a2c35dfb), uint256(0x073380bdd943f9849c2a201b63b4b0b201fb974029b042793926deea0a0ec1b4));
        vk.gamma_abc[301] = Pairing.G1Point(uint256(0x285c0d3cd7b943373b4fc984c4b12571fac86b04e761ca923795a97449871f2d), uint256(0x2c200ee59ec85f7c39581c814b25fe55d93825831b79db6167b6ef2e26032428));
        vk.gamma_abc[302] = Pairing.G1Point(uint256(0x046a542923a773fb7cefcb760b45f89b81bffb12490f80186f667d8e8be3725a), uint256(0x0c10ae2e0eb50f210433905433afeaed24e9e6121207f5405c455a8a54b6eea2));
        vk.gamma_abc[303] = Pairing.G1Point(uint256(0x0640255c433a855874478dbdce50223c1811c129c59940da56e46351c9f3babb), uint256(0x2e1abf9797e1d08a0e9fa41aa3d45fa9b731fcf03ebf9a25e7576e0e2a2b8585));
        vk.gamma_abc[304] = Pairing.G1Point(uint256(0x3015eb5bd9bdaec1dd7962bfbc1c67d99ff08df323ac437196469de9239cd817), uint256(0x2d04abaaf4445a7dd3fd0822ac89a7f0d0d0a7198d413cbce0c8256435e07dff));
        vk.gamma_abc[305] = Pairing.G1Point(uint256(0x10dba56d0fd4c4cca0e2fef564ecf3dc21fce6007a65bbf4a58e1c267c4c8e09), uint256(0x084853743735b2810bdae27b10dc788fac73e0a7602c226ef7f0f270a17b8af9));
        vk.gamma_abc[306] = Pairing.G1Point(uint256(0x0cd09e222665c08b572ec90c5bfd53eaae30372da11297cc6211dd55de83b027), uint256(0x2182ea6800b49afd7a969178336690ba5336330e1fdea526a4144ac101ce6be0));
        vk.gamma_abc[307] = Pairing.G1Point(uint256(0x0b85c2db24a63fc077cf2b3e5cac397c9858b2fbfe94d4ab045b97c58946c27f), uint256(0x25c908471072e8c76cc28885bbd2ba057bf2d0754a093c94c9dea9451887707a));
        vk.gamma_abc[308] = Pairing.G1Point(uint256(0x1b31156b95346219c6b21cd7c0fb75e2a2d1a7d5df462645a642718dea4e7f1d), uint256(0x115de8d8e881430e620eb1bc9fff205ea17d464f34de461cbb95451149136eda));
        vk.gamma_abc[309] = Pairing.G1Point(uint256(0x18070d220ba496fe234b90bcd63948b6e2cbf99c1cb40990eb442098864e4112), uint256(0x2920c00a1b81075ba34c96c19d8116b90d557a577f55f18e6f493321daa66960));
        vk.gamma_abc[310] = Pairing.G1Point(uint256(0x1c4478678b5e53f051071b4098d1c0faf7625930699249b0a6e69e1a7450342e), uint256(0x1cc58aa17935e2a6138a95a1ff4542cf8d814c0a1197d3a9cab42e707af15988));
        vk.gamma_abc[311] = Pairing.G1Point(uint256(0x0d25393c3526d2f3c1e717409a1278e0c931b20521ce13b715e03de89c998c33), uint256(0x2626dd14591f1006364bc40f2c518d809f33d8d48783bd2db3576c18e05ea49f));
        vk.gamma_abc[312] = Pairing.G1Point(uint256(0x020f145ab44db1c37fdc1366422f083ac250a2c7ff2472bb0f62e05321cb1cba), uint256(0x211c9e79df60e00a249425e8cfa04743621d11e3ef4fd678067cf7cfeba18742));
        vk.gamma_abc[313] = Pairing.G1Point(uint256(0x2b878e57bb84ed598eab02db56bc3a7f8ee8277488097b32f9a6a421218bcbad), uint256(0x05d608d9a28eeb8de75e4febe2563a2f8a842e701511d530bbd247a50a3205d5));
        vk.gamma_abc[314] = Pairing.G1Point(uint256(0x0c2515997909555e0419c7e505fcae2cfe614fabfab0272bcd29ac688f0ddb34), uint256(0x098ec8128ddc06a0381e9f0d4338beebf824a60fa0626bdd3d9f2ad181e81734));
        vk.gamma_abc[315] = Pairing.G1Point(uint256(0x0836df075b480440138ac87eb9a0d33026e208f094dc2531a8cfde18ee4dc6bd), uint256(0x03bae6a30c2f3afdb70656c8f84e04024ed2eaad4a800bc6ec8599c34506fcae));
        vk.gamma_abc[316] = Pairing.G1Point(uint256(0x1f308e7d98e2c73870dcde151ebc124930aae4d8175c8c709c6b09ebf70473e2), uint256(0x0bf8e205c54ef8a9aa7a82bd2d7a4d64e1dfdc77b89044b75dc521ef31308fdd));
        vk.gamma_abc[317] = Pairing.G1Point(uint256(0x242b4bb3b83b86d3b551914cb4de7fcee161ba5fc86c58f790a2de95f59c506b), uint256(0x1ec96f0682e821b323e6bc3fbb7325ddaac788cfb5347e2eaef41323dfe9bde2));
        vk.gamma_abc[318] = Pairing.G1Point(uint256(0x09c61d15f3873db926d824d630cc5f81752ed0cb50456ffe62f40add8ef949e0), uint256(0x1d6749177f7b11028e4c387244328b2c1a438fe14a8c6bfd140af96e82396a51));
        vk.gamma_abc[319] = Pairing.G1Point(uint256(0x2dee5a1247ac7d762828fbba158eac95c61accd1a9f1a0829ab7b38e22fe75ac), uint256(0x1daec987d61316d6153ddc20fd9bd163078984068053fdda1f2505e7d531dd2c));
        vk.gamma_abc[320] = Pairing.G1Point(uint256(0x282cc4c503510ac3041f8c49fbc743e4631c461b8a31c1cea1348f56f448af10), uint256(0x1f8c73fc06407a495f6297272864e5abf8489edae7a3c0ac41f60e5beed480d0));
        vk.gamma_abc[321] = Pairing.G1Point(uint256(0x00e050dc3711710b8c053e78da9902ef603e00e5a3ab8026d00f6b8b0a1fbcc6), uint256(0x207a13ed1baf32445752d39f9b7a3212f70764f84876bd0fe8970df8cba68038));
        vk.gamma_abc[322] = Pairing.G1Point(uint256(0x2d99a5a1438690a300be8ae387da69a3a1474931827078d9ead087906a86a63d), uint256(0x2f87d20a16c6137b1fa810533503c1852738a8dc7f71f43f57fb59980db5a000));
        vk.gamma_abc[323] = Pairing.G1Point(uint256(0x2e603cef84a5a45b832d42ef77764ae2c7f15e42bde612db71e8137bc774ec42), uint256(0x1ba352eff1891bd026dc8a25690cd670fd57d0fa2388cbfd82c6bbecfe6b61b5));
        vk.gamma_abc[324] = Pairing.G1Point(uint256(0x0f61f612aeaf50fe588f770099a0dfe849bd3ebc26cb9451f5eb4cab42e19190), uint256(0x113e2737250e01d6ec8fe3c2d58775c399bfa4f4a10d2ac52d07d74aae8f9556));
        vk.gamma_abc[325] = Pairing.G1Point(uint256(0x090812120a21e5181d1dcafcd97a7295ba84bd852fd122eae7a3873ddc480319), uint256(0x0628c75bf1d46e6e8e56a8c8318e88e03bf7b62f4ca76b84032db45c88c1b952));
        vk.gamma_abc[326] = Pairing.G1Point(uint256(0x2e126856691c292581bb2525a233abae888c6117c2bb38e46c93127ad7fdd0a4), uint256(0x253980e35a093940f04e44bd1b81a3cc2db605773b10d22d04856829e2cc7e54));
        vk.gamma_abc[327] = Pairing.G1Point(uint256(0x270b6b862cac5b2a05fa9d88e875dea5ac4c653ad239a1fcc163a5004858ab73), uint256(0x0c8da1ba32e5ae295a30cf43215aa67652df1670a171c01a253f0139f1d960d5));
        vk.gamma_abc[328] = Pairing.G1Point(uint256(0x2df49d8c98cdd8f7e4b90ed81e3a426404c6f8ae8e7999a5fcb7622bb148b63a), uint256(0x0fc4e4a1aef81b811fd6521ed3b52a5b94eaa67c09b9e33dd7c05fa793efaa75));
        vk.gamma_abc[329] = Pairing.G1Point(uint256(0x0b14e0b3310fcb212d671f1adcd8148777317505183c47062c3760baade0436d), uint256(0x29faf4afaf4fa491a51500fcbc5ad823cb58e103ab6c728633f1b5614f84c930));
        vk.gamma_abc[330] = Pairing.G1Point(uint256(0x018315f6722464c0e2e58d7d50ed3c235d93a5435993c33a330edc476846fedd), uint256(0x2efc45a10a4ba1350681f1e56245f30bd504d7399404fd0fa585371e459a7fa8));
        vk.gamma_abc[331] = Pairing.G1Point(uint256(0x1a947a03d3fcb9e66256277e13513a14575e90f6f28e398297d8091cdd9dcc9e), uint256(0x0c91473dff189c77134af1286804ef37bec032eb3443fad9bf0c2a7da4f6616c));
        vk.gamma_abc[332] = Pairing.G1Point(uint256(0x18e57334eb8ca65cee9a450f5bd26e6e52d72c5047bbe710c89ca4903799cdb3), uint256(0x0740263f97c92c0321da67af4520a5818724f19dff8d833540b529c349c12b82));
        vk.gamma_abc[333] = Pairing.G1Point(uint256(0x1a1063ff16dc0f82d72b16ef3a65647934a34063723d1e4105a8761e3ca86f97), uint256(0x13ba126c27613bf9a504e10a40281c5eed335d0c321f6ef315fb3a1471f89b5c));
        vk.gamma_abc[334] = Pairing.G1Point(uint256(0x0ed390b49fe1ddd2781272b888b01c8eee5dc359b4e611843f3a82d35a3f6d55), uint256(0x07a502e3839c981c1aa8b214731ebd1c0099877424b69137d9e6c4e6a7c5c57e));
        vk.gamma_abc[335] = Pairing.G1Point(uint256(0x293e068a4fbc9a277265e0d758870c28cdf5fc8799bf60158ad725a2bd0a0a1e), uint256(0x284d1692abac078b49e46b505eed97da0db891981f330cf3c13bc368ca462301));
        vk.gamma_abc[336] = Pairing.G1Point(uint256(0x1592efe2bff71a68ad5152c266525bb418bef75b61802508662372def28dce9c), uint256(0x2929ab2d4dff94ef22b62705bf4157d115b5db3fcd2977c1154f567bd824e39c));
        vk.gamma_abc[337] = Pairing.G1Point(uint256(0x0419c423cc26246c8346f45debcd1ec5f19e04390424a49d4dfd9cec3847061f), uint256(0x209517063399616f90a0d16093fbc9a7db17d8923d8195ba8b70734f498f2db6));
        vk.gamma_abc[338] = Pairing.G1Point(uint256(0x1c31a07377a543700092e135fae9c8297558792971305c93007955b009782fc5), uint256(0x0c3ba40a9c85fb012535e0dc6b86a04cfdb2f293e5011d4e9c24bded5f953c3e));
        vk.gamma_abc[339] = Pairing.G1Point(uint256(0x2a7f8ef3497ff2d1386790e7defee5ea3aa867ef5e1117a7af310041a1eee673), uint256(0x078213d1218b860d26670ac5e722c8e5c42b0f42c775c51a7893b82ff52c28e2));
        vk.gamma_abc[340] = Pairing.G1Point(uint256(0x0bb10e203062586b53ba81b4d53fc0e4dfc6b3edde6143e47bd3396409d79b3d), uint256(0x10dd6d4df269b9ebcdc092df81bcac9db3257d5961725057715e8966a82f712c));
        vk.gamma_abc[341] = Pairing.G1Point(uint256(0x08baf8e7a517bd04b76d847e7a27652829d4534dd7b039932ad223cb6398b89d), uint256(0x1a6a9f66ef1a6aca69e86b6546bbd477780bec54f84dca7c9fab05b7f44e4cc7));
        vk.gamma_abc[342] = Pairing.G1Point(uint256(0x05d6b0a14b88dc6abfe023cf25d333d3e8dcb6cfe95f68c66bc95f1bb60ff2e4), uint256(0x0714a06cda76a9d4e2215d362180f4eab47d902ed996ffbadec995c3da905ed4));
        vk.gamma_abc[343] = Pairing.G1Point(uint256(0x049a480b2bcf73eaa7384a5b708f268597d8515bd2499ff28df50b10c92aad7d), uint256(0x0d075c75496404b4eff5e79b5cc60663d394c582cf4a1a4b421a55aa78c325c1));
        vk.gamma_abc[344] = Pairing.G1Point(uint256(0x0849ade90f23f3882013f2e29e93cd847d0ff518637e7fd2c9ca8e93b326a3ae), uint256(0x1d5d28f981b06b8e5b3960d378439108506705ce4c338408c81f1b8bc18e23c8));
        vk.gamma_abc[345] = Pairing.G1Point(uint256(0x1a8122882ae2b72c2bbc51825ae7dd5ec562a22d697e8f7bc211f5a6e6a05fc4), uint256(0x2e01474008d5b9342edc172ffef9e9b465a462e31d81497c8357b8d2efb8d8bf));
        vk.gamma_abc[346] = Pairing.G1Point(uint256(0x1a80fa77286158e1794fe8c09484485630be31b603e0344eba830c881bb16867), uint256(0x2e8d37a00f89f3cb95b5ce830a8b522f352b347d2b861531612639c06dab6dc3));
        vk.gamma_abc[347] = Pairing.G1Point(uint256(0x0ac884672a8c5234aeb1a3743b1cfae511378058db6837534f298287b9665867), uint256(0x0041fe1b780906f3205ddd62860888158a8d833b09ba49dfd7f939864ea27f66));
        vk.gamma_abc[348] = Pairing.G1Point(uint256(0x0c1c198ebe4e74aaf7cf7282702e9bb529df5050dd5ec01dafebed5543b06d92), uint256(0x13dd9aead46a844ed35f5172e67fd66c5e159c0bd50706d933b75063509735bb));
        vk.gamma_abc[349] = Pairing.G1Point(uint256(0x066410fde32daec9a768e37979e54c862d9136a7613d8615be6c54be63850adc), uint256(0x2e9c98018d295b9430f0a516aa95f4913972cefb482b64a33b61c0c8a819608d));
        vk.gamma_abc[350] = Pairing.G1Point(uint256(0x27758e21cdb69d2be1d8778753ece04df8ec89de331b2ffa465d2b21145d00ee), uint256(0x23225d28a1c694b8019a599097bea81d4e1d1c7f46b6f1a8fca9478713f38327));
        vk.gamma_abc[351] = Pairing.G1Point(uint256(0x1468e198141327efb92fbc0670bb6b1e4cb4d5fd36c8bd24bc016b88d1f90797), uint256(0x0d7707822b1648c80c2f6eccf6cb6c22eee086cde56479d9744aba2cf6e51066));
        vk.gamma_abc[352] = Pairing.G1Point(uint256(0x11c58a9f61b821c2a0af6c2333aa784a4ab69dbf567f46aeecc56ba6622c79b5), uint256(0x16d0ba6e63a35c17f83a460857a0dbe35f044203ebd78aeb6d20a78e9a248325));
        vk.gamma_abc[353] = Pairing.G1Point(uint256(0x107f08cb69347212cdeedcae7b24a03041184c63955ebc4576d58977c357f24f), uint256(0x0779c5e57b06323f68ebd89adc8b8ab8a04995128a68b6c64934a312f9ad2246));
        vk.gamma_abc[354] = Pairing.G1Point(uint256(0x2195278a65ea2494b105b084c4e967ea06299b197da79243baaa268d462b05ec), uint256(0x201f5da84218c66849aec5fc3d21cdbea6c9cccf5ef4edb5aeb18883584ab8c1));
        vk.gamma_abc[355] = Pairing.G1Point(uint256(0x19f5656f9622412078cb184f406ce7e0a3792064f36c42f193a58709be076012), uint256(0x1e0f982800e0ee0c303d18429477e87d6601372a0da81d70d8fea7d1cb0c2d6e));
        vk.gamma_abc[356] = Pairing.G1Point(uint256(0x1369310c021a56476e47bf6e76a2216ba2937da09b363cfdea97a5b4ba007cca), uint256(0x0eaa91970b9cc9b2075575856aabd300d0837ef6d4137f0079fa392810d39db9));
        vk.gamma_abc[357] = Pairing.G1Point(uint256(0x0b75e39b50f9bae505c792b5bb086c6a801b18228ae08afc47daa518a4827200), uint256(0x2996e2eb2e35f592dd55b67a29d173968198f6fd4bdd8016db8093213956fa3c));
        vk.gamma_abc[358] = Pairing.G1Point(uint256(0x1abc5698bbab7527e3ae5378cffd549fe54e936e0afaa8da703a34ad1f699231), uint256(0x1de29c19377b5359b11839ad85ab3457e149b0ada3b9dda8c25f3612a6169ffd));
        vk.gamma_abc[359] = Pairing.G1Point(uint256(0x0ad62c5d6e5b309478f029df472def7a72d40515e09daf077a29bb13cc78fff9), uint256(0x1d1053f5b066118557cfea145eeb5d798873bcffbdd71ac2eac689162adf1501));
        vk.gamma_abc[360] = Pairing.G1Point(uint256(0x0386dfa08dc66a8ef72c4d83bbd4137562e76f99d4873a4492c16ab1b2e5f8b9), uint256(0x2e92bc95254a34eb056ecd22da5184333ecc37ce0fb264613ad3d977570ca456));
        vk.gamma_abc[361] = Pairing.G1Point(uint256(0x10d69b266efd1f2cb0d2f98e70520d542d88678a82f48f9a8fe164dda371b92c), uint256(0x2c8a0d85ce9ae4d3638821e5b61e5dd8dc2b79c50a8abbb79a4c49b9fecc2e87));
        vk.gamma_abc[362] = Pairing.G1Point(uint256(0x17a0e4defaf4974e152e81bbfb55d7d5711690c157adc9b1376520521d64e2f3), uint256(0x077aba4d7aeb572f179871b8b5b570ae3d69ca9b4d6c58dcb9c03f0573195422));
        vk.gamma_abc[363] = Pairing.G1Point(uint256(0x03bbe807ef1892181066efc10f46eb28ead494bb29ba53723bda4ae5a2202fb9), uint256(0x2041c9ff0903d2e316bdc44266ec0109fb1058de9cb5c620db168cda84dabcf3));
        vk.gamma_abc[364] = Pairing.G1Point(uint256(0x09a2751340f2a4377f9175bec71d187af6c624a13a06ada960003c9c32c950b0), uint256(0x03d528096106abd59d76676cbd56310c1f79d8f92ae8d3e0baa790c2a36d4c16));
        vk.gamma_abc[365] = Pairing.G1Point(uint256(0x11e8c961912d655899f0bb5a83b15ae78fdd08641213dd6f951f0965dc56c8b2), uint256(0x252c2756457372bcbe536dae45e803d7f554b5a6f9a30e0d7aa5e00950e6e8dd));
        vk.gamma_abc[366] = Pairing.G1Point(uint256(0x29bbe5e5f5197f4594b6bac7d223058dc8bb476d7838d4e2ec8b0929b5d46be7), uint256(0x039fdfc30e3c4b81313a1cb4c5bf532a8bc9b9134b67ae129c58a07177814981));
        vk.gamma_abc[367] = Pairing.G1Point(uint256(0x0fd6106f9e3118d358e1418d7607e932c2f32e2b6575f9bfc21dbd404baef2f5), uint256(0x08dcec0e1de3718039c92a7bd86c5345a8885bac895be2470536ec3028955492));
        vk.gamma_abc[368] = Pairing.G1Point(uint256(0x01c8c427971a0d5e929b94ee319ce9773485ad14d90b2d292e7b36dcd746cb12), uint256(0x0f70796835c72a2708eba7262db3faf51a4fe74562f42f59858874a1a1cb3ac8));
        vk.gamma_abc[369] = Pairing.G1Point(uint256(0x2ceac95ed34538c0d558b0826b9f28a9c9244ce120b091ecb8d715aa9ec68def), uint256(0x1343e3e37c1a4cbb9606037dc3e6c766cb5713727ede70928907bc36da651619));
        vk.gamma_abc[370] = Pairing.G1Point(uint256(0x23148bd6edc4f7451e28096a97b29aeb7241bf80a470ab6ad0f89726094815bc), uint256(0x1672e1df1b3b5a874382ad27121ff61479d34b3af905de27c8b9da442b6aaaed));
        vk.gamma_abc[371] = Pairing.G1Point(uint256(0x125bedc4289a774f520ad34e71ae440d4073a92b6c9516b27a44d013bc64c843), uint256(0x0b59fc162677290dda2de5272cd202ae83eb5524f94321b1f6ec2d4f3aa3646e));
        vk.gamma_abc[372] = Pairing.G1Point(uint256(0x287fefa58d7a26a8a3deca8993ce8eb706587200ce1a1a33cfc3a577676a3e2e), uint256(0x0826e31c3910e53e5adac35e10054b2544b2d59efd365b7ac347a0e10d7d6ffb));
        vk.gamma_abc[373] = Pairing.G1Point(uint256(0x050a92960c94a2b77a0190914f39c72ad3aabe62fd20c0364162c441753b4686), uint256(0x278fb1d42aa045b8ca5bd35e2d8376c52f2912980e3092a6a6afcceb218b0c50));
        vk.gamma_abc[374] = Pairing.G1Point(uint256(0x1b7768b6f23aed85be6d76dc39bea4f2eb9d4373e08de58e2c1d8e1bc05dc095), uint256(0x2a01d00dcf3a55460f4ff71137d68bb94b29cd165321a3cd7e11e5a54780a6ed));
        vk.gamma_abc[375] = Pairing.G1Point(uint256(0x00737dd0cbe9f640e2713c892ac32ac31b783e04ff6e2ebf908660893aba4963), uint256(0x0545f1eb434bd027a9d0b075429b15c6cacd44dba1dc0a87d93982effe08b48b));
        vk.gamma_abc[376] = Pairing.G1Point(uint256(0x03d3fbb5a9196cfa532a63ae2ce99b4a44f43372c6fba0f62e0833b2cddc5427), uint256(0x0f6b14b589dfe4b0703b290ce0c4b8b0a4d4b98a1b9d7a1ceb7caa0b7a4e2e22));
        vk.gamma_abc[377] = Pairing.G1Point(uint256(0x214b923e0d42a007c40666226fa76830844a3d17b6d7b2a929ac452403d540c1), uint256(0x2b7cdc8a8404de0702b75f756f6487183ed08051ad1f8695db05819dfc363c0a));
        vk.gamma_abc[378] = Pairing.G1Point(uint256(0x0689591f1e7783f867af9afb4b7a0f56cb7cb738e9d76b60e0556b1d9820c8cf), uint256(0x186f5bf9680143f45f44d724129d51e7c2482008be554f090467ce1233c0619a));
        vk.gamma_abc[379] = Pairing.G1Point(uint256(0x0307013c39e15aaaa64ca09963d751a384d0c755bf946261cce828d9a64385c3), uint256(0x1eb27ca7969de6b71bff006b28a4c3260184e21d16812439e93de39aec1c0456));
        vk.gamma_abc[380] = Pairing.G1Point(uint256(0x1f2dcc663ae69df5cc010cdb5b6c8481b3b597591d59c93a7429e32aea64f2c8), uint256(0x28394b305221373d01ae862247827120498e463232afeb1de2945a7af9beea36));
        vk.gamma_abc[381] = Pairing.G1Point(uint256(0x065d5bdf1467b8ca4e25b92400abd958928f26aded62919821da293234348631), uint256(0x18fd01c9769f1aafde58a26802cc56d57c2acd7b30e250b5e6406047274a28eb));
        vk.gamma_abc[382] = Pairing.G1Point(uint256(0x18c2aba707b8416bcf4a051e3ead62a1673712dfe102979df0a04341a0d5c5cc), uint256(0x2dffc15ccbce07382e9300c8f72b9eea20d7066926437714371cfa3b00c02519));
        vk.gamma_abc[383] = Pairing.G1Point(uint256(0x2ce66682b4fbff89e348332de722f8b96d53db36a1900e5df817d79a7349ee95), uint256(0x30358f2c70a77268e7c0e4135f7007050c69ff1846024f9762794955f74d7359));
        vk.gamma_abc[384] = Pairing.G1Point(uint256(0x2d9d8ada0aba4b4816b95f9585a157d0f09ff376da25e8b995bc0e0bdbce4c68), uint256(0x0d84b69f33abd9cf3bd63f16a739cf746d853651c84b85e13b6b56cbb672b9aa));
        vk.gamma_abc[385] = Pairing.G1Point(uint256(0x00c356b4ebd6e59f4e5646ab0d751de747826ef022af272d6df0f307efe3b30a), uint256(0x124e8a3d08fec0b04ef9c13ca951ba015e8586a6f3739bdf177d584762bd8fad));
        vk.gamma_abc[386] = Pairing.G1Point(uint256(0x027d2dc3108beb246f63445cfc09a11c63f0dcfc5eb164c9175af69e38c918fb), uint256(0x11f5ea468a5e3e2772656413057778c37777bafc321fcf636c1d1a64d0e94670));
        vk.gamma_abc[387] = Pairing.G1Point(uint256(0x2155413728dd59742ed3a06d41b590d14f1fd075fe4eb40b9082a9dca11634e6), uint256(0x09c308585425f203a4e08fcf3c6c06ee9998922c6252c7201e6d394ac215ea4b));
        vk.gamma_abc[388] = Pairing.G1Point(uint256(0x2cf1a243ab737fe1ca81c3a5230bca7a8402c7f522afbacc2b819da333a75569), uint256(0x0af75f2315e645724ea0415c5de8e34a787da9bd0b5d4a9664dd30c6595915ea));
        vk.gamma_abc[389] = Pairing.G1Point(uint256(0x2e8290c243f46381d3ac3d2bcd195a9f7b8befdf9a0a5c502b61013a55f3572b), uint256(0x1957a9a7efb4636b29cba1da08b733f36e0234c78b77f6aaab93b18171d3213b));
        vk.gamma_abc[390] = Pairing.G1Point(uint256(0x037c87c4b7a9462df34b94bc20e636ff11c1c318fd8429777fb0067c63a53bc0), uint256(0x26a4e2486ef6b16fb4db5fe400dbf2ec4ad9a2f6513ff72aefa1fa7d1fa00c67));
        vk.gamma_abc[391] = Pairing.G1Point(uint256(0x2729f285fd81f329ee364d1d9269851ae89ccd2c0d83e61b6a5d85a59a5e1b3b), uint256(0x1623fe9245122341fa7e316ecc8aabeb675be80143dd0792af72edc876824427));
        vk.gamma_abc[392] = Pairing.G1Point(uint256(0x1fe3f06a7ac5d17b977e6c59bd8763910c0858b75caf74e121c96894e3b8c7c1), uint256(0x05c4de8024627598e6974a26ba6c0b1afb01b65962a237eb88de5333b1848e97));
        vk.gamma_abc[393] = Pairing.G1Point(uint256(0x24b65a929a70ff6a33b1a8c37d5fc5daa0da0b9976879a4a95d1a4ff5e94e0d0), uint256(0x028715c4569ae5eeb3fb96d0bd24648392a50e8d6ac04a0407a11b2cace87f72));
        vk.gamma_abc[394] = Pairing.G1Point(uint256(0x0d5224fcdc88f9345adb53af98b9ecc184857c66a79c925e4b82a5f690de863c), uint256(0x1f2311a59e80465739eae3c58324274d80f4b8ee40d236d321146bb5f1426b3c));
        vk.gamma_abc[395] = Pairing.G1Point(uint256(0x29f64445022a658ee58494500b7eafed45adfd650839de8f2327ca3593904fe1), uint256(0x202682d9158f39c0c46d9ac18f657f73c4820b96c62b5112d2f5f88090bc3f68));
        vk.gamma_abc[396] = Pairing.G1Point(uint256(0x068daac0d8afaf3e1bb2787de89b2b4387a3a12038dcb865d357e9ba5568efca), uint256(0x28ce1067068e4cc9e65286d50dbfc1cd10cfe1b1a8e3cb1479a562f6a3837cbf));
        vk.gamma_abc[397] = Pairing.G1Point(uint256(0x02387173181dbbc3fa8ec9bd841da3fc2712405d4f063a2eb05bfa688d58c049), uint256(0x27ff4b647feaebc254a4c79c2dd52634ca088093ab7db4105b9f6e0e73db5919));
        vk.gamma_abc[398] = Pairing.G1Point(uint256(0x27871c48bf549f66fc3878b02b961c6630f77d775570541cfead41a5f429001c), uint256(0x07eceb46eef5a7ba8b957c61bfff9bda6a1512ec92634750bd07a11a22b6be4e));
        vk.gamma_abc[399] = Pairing.G1Point(uint256(0x1ce45b3498f9c31a53034c3280d6dcdb6a0892781c0e5d6aeb00050e7e9cc811), uint256(0x1a85c6fb1b0103a8e2a9e6a8c313206b31729bd2631ae4fbe26dfb0186771f8f));
        vk.gamma_abc[400] = Pairing.G1Point(uint256(0x07d29bf70d5a06e409ee823b8e1c754cf87dcda97c8dbff99f79c7dcf4c22219), uint256(0x0186bacc296e8b41344666b3d30e130f09b5b6062e35bbdb2150c4acf985c8ce));
        vk.gamma_abc[401] = Pairing.G1Point(uint256(0x0750d40525bccc4de94c93085df436cae9d970d695fbb574eb9bbaddfe1be1ba), uint256(0x1f9e9fdc5055e2ece782af16a7eb2ef11fa9d81e89370999df2713d343d9792a));
        vk.gamma_abc[402] = Pairing.G1Point(uint256(0x167bf31ea82404f9902c68f4f9638d137b66dd203ed5d5aea3fa79cac7317a84), uint256(0x1fbfa81253e03f72ec023170fd47ed022e0fd5b83eee2e1dc18daaf31dac23ea));
        vk.gamma_abc[403] = Pairing.G1Point(uint256(0x026eb7e04545ab7dfdc05479ecf04276ce875e888828d5a64b30f60233bd7b43), uint256(0x207793ff0eda3938e6bc0377028831d85f55fa9a8da32bea5ef0e5c6dd0399b9));
        vk.gamma_abc[404] = Pairing.G1Point(uint256(0x237277d59f72efeae0f5b4a7a45afc6080812ec16273696efad9c343e22d29d6), uint256(0x07119bf5ecb330356e631813fcbec33e0407782e9ad0f15e534e635b2f5669ab));
        vk.gamma_abc[405] = Pairing.G1Point(uint256(0x12ea581fd5ae7b828e63ae7d1144d9d1723b22895236f6b360e1c093ea7d1fc4), uint256(0x1acef4088657145c1043e07fa0da3ab521185f7a0ab3d20f4357997ceeb7ed7b));
        vk.gamma_abc[406] = Pairing.G1Point(uint256(0x0b16474a7136ab2687413bd1fe778774438381a8c352c67a8daa3e6d52bbdbef), uint256(0x24cea19ecb0429f14915c6c6b06a22ab5ccec22e3e8b1e577ac9b32d39636a80));
        vk.gamma_abc[407] = Pairing.G1Point(uint256(0x054ddd292a4e3a9f89d5451e5e45f008fb37ccf57ea8c5489c369bcbf26d711a), uint256(0x083828b9f2a830e9c8b18ed3fb6699b30bbfe386f0ef792cf3beb05e5f526527));
        vk.gamma_abc[408] = Pairing.G1Point(uint256(0x0cf84ac53a9570d7d221b1be21ca6414c07b99b0b71e20638ac6f338d43fd063), uint256(0x1844bda9e171049e28fca440056593e73d2603134d015ef26effc8771d2ac2ff));
        vk.gamma_abc[409] = Pairing.G1Point(uint256(0x2a8ce67131bd7cab70620a479b0db83567988da8fedb2dce9f9655029e89f2c7), uint256(0x0c7e8bcba7b520cfe83fd344e6ba81a62fbd62e5983e93f247a6fdae3102a26c));
        vk.gamma_abc[410] = Pairing.G1Point(uint256(0x036f2df04a6d2147dd44ba7e0a18211515cca778bc8019879cb1b962736f9fec), uint256(0x1a6eb01fee1b28b454d3016c39ad6523ff073ce96ed4a3fcfcb1f4fd44cdfc76));
        vk.gamma_abc[411] = Pairing.G1Point(uint256(0x019894e8421418f6ead29605e2f265f96c315c5fbc702702b2d5d4e14922bb41), uint256(0x2b7e1c1d3896b05853425ec9473d49f767507e948308db3fd5f51a753268b280));
        vk.gamma_abc[412] = Pairing.G1Point(uint256(0x18879efaeb8075f305935737a0b04e03a45fd8a04905f296af56892f6145490f), uint256(0x0204d20e237933688fe845835b903da98bf8ef0ccef1be790f4b5fb69f993670));
        vk.gamma_abc[413] = Pairing.G1Point(uint256(0x2e3149427ead3b6bc1e12969a6c42bca20567eb2c282379a212c8d53abfb56d0), uint256(0x1e9003b511a40a73fba9ed35e309b9c904365f2101cc473c676920344ce5c19b));
        vk.gamma_abc[414] = Pairing.G1Point(uint256(0x16abd25d6b5666da89e5867523ea0eec140c76b144e27ee14eeac2b8c9e03e50), uint256(0x1e3b9145567dab21b362b0379a96c213cb429e8e42bb0fce9bf1bc694f055722));
        vk.gamma_abc[415] = Pairing.G1Point(uint256(0x082209a0980cf7d92a16bc57b62b6e9a8020973cd1e7d53a00be9746ee9b573e), uint256(0x133ec6005fdde0ad724cf429afac77fc3d5871cd84937184966f388a7cf217b2));
        vk.gamma_abc[416] = Pairing.G1Point(uint256(0x2af84731c5afeb46298f70554a41fca08eb3cef2b3d8d9cc96b341709daddd3a), uint256(0x14375f5ed39c078eca7f071af16b033a1f2fa0c1adc78b758c9f03f1d5df0aee));
        vk.gamma_abc[417] = Pairing.G1Point(uint256(0x23a5dcc875d87a06e40b5b2486a1fbb0d471414aa69d6cfe7c1f77c1eb8038f8), uint256(0x113e767c776c153cd9363482a2ab24838f819c712246bfe9576f9c54f91805f0));
        vk.gamma_abc[418] = Pairing.G1Point(uint256(0x081e430b7336784b462e9183b2128662e60edb17815b12c4d4962d5d985d1c62), uint256(0x1c56b4251c790965720a92913a9e2a7f1df7970c9941888150d173f3f611cb85));
        vk.gamma_abc[419] = Pairing.G1Point(uint256(0x1e76c0ac89f7cb7f09aeb26a7213568c709316168baf1870e240fccb203a2299), uint256(0x250cbbcf687d5fb1047bd8bb4c90283590dfed9bee75d391610062a280dc3c75));
        vk.gamma_abc[420] = Pairing.G1Point(uint256(0x252b93d0990f37b50d0a1899adf165806d363d99666bf74c9eaa9327e7b884b1), uint256(0x06a7e18ae9763af51e6143450170890cc4877217c0d97feac1f39da28dd4689e));
        vk.gamma_abc[421] = Pairing.G1Point(uint256(0x2362e7822e766ad48336f0d0a63871ac21d3997a157f2f8c7755001f769a59bb), uint256(0x010a7f262bdd45fd285fd6c7eb14c20863d772ba16968cf95c9a2ac21df2750f));
        vk.gamma_abc[422] = Pairing.G1Point(uint256(0x19c9eebe686a1e2ae1fd09afff7e91ffb2c3c8780b3d99217128da9660df3ee6), uint256(0x0b7795446372e85ee033c26c1a8412938353ca218b45af60ac1ed8af302a0b03));
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
            Proof memory proof, uint[422] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](422);
        
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
