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
        vk.alpha = Pairing.G1Point(uint256(0x09f67f083da10c12583b441cd17b0546925b0e1ba79384c7143be3120216eafd), uint256(0x0e99e51db2eb0eba6589ad9a75ca892777e79e1c301b27444e1b6cd8d651d3c7));
        vk.beta = Pairing.G2Point([uint256(0x2ae40bff5d503cd91d1548c0cfd968a3b2b4182d9017e2e77e63a50ea0814f59), uint256(0x19eeea8a015a68626842126d5c031e04cf994e1667809a166ad8d317dac851bc)], [uint256(0x1fb29db0c69e311e6931c3d1fa23e138c64fab734b916300f7b2d933f16460f1), uint256(0x10377245abeadf468ab0efcb7ec14d3b49ce1edad456a24a7baa04804fbf36c7)]);
        vk.gamma = Pairing.G2Point([uint256(0x084946de0f0205b167949ca27bc131ad2245848abcc61cf7d5fe163267da06d6), uint256(0x0c00706bbdc571b5692d8e781fba6e83034c462dc18504640507b5002eb8d7ec)], [uint256(0x0bd1d1ae1447357144ae75d3dde5a9e82e1f6cd077dc9675e9e92e4359e3ed1c), uint256(0x2f245c17ec7b85561bd5bb5c33f6c604fa8613de5e9d516418599464558ae260)]);
        vk.delta = Pairing.G2Point([uint256(0x2db00310193c1cd38e9a99875787bb2b1df2a2433012cd0f759ce78321e70ead), uint256(0x2c2be7811a96759125fd31fe0d426336194b709d2a97e8aa5f1eb545dae634fb)], [uint256(0x2d7ac27322f4537b814f2a94c6312a04ae92fed2140f77fa8e69a9b406ad7e2d), uint256(0x24fb35ea2609e3e6c47666d1d329663b29cab49aacbb4a86ab8abc21f7ca4d05)]);
        vk.gamma_abc = new Pairing.G1Point[](109);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1cf3899a27f312850c39c0b11fda9f89d2a8d2b0bf2708e454fac784fb198c91), uint256(0x2484a3532d3c21d74c11e1c865e7ec8315ab24c2ad86f3520356bf7b97a59dd1));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x109c17f84aff35244e61efdb63b11fd071959cd0fdb891568c94ab44374d5d1a), uint256(0x21cf6d7dd1117989a0db89cb26765a4d4bcaac0a5bd07a8d25c1df5149dc10cb));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1dc61c764538e3ac3b590baf7a3dce3bfa383799d08d1939d0e54c8c8dfac182), uint256(0x0edd2c7b2ff58972b6a82299473209ca51d590bcb49db19ee1ea2e1622f0d0cd));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x09f361e10840ebca929d1072afe2da8a22c07cb35eda049a274ce33595caf563), uint256(0x216ba3bdf5caaaf3d4e689eda0daceb8972ed0e8534a7fee5978d02001558058));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2293d568aedc9c964d9908cd867d357753e5e843f010372b0489e7d19ac0762d), uint256(0x1e003b39ed50252034a96b221df302bb38376fb334765882c2edcdbe36994d3c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x17595151a099c25b1c14b1db6a1e4a57cd9cb38797c2608df65245031c390e76), uint256(0x1486e43171cad5a948debfe7dcaef8e80769e919da735e4c192fa1f85d71ae65));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2e838a7cadf864c455dfedf3cd6186aa15c35452bdd2cdc7764954b6a46afa05), uint256(0x26ecb3ebd1307f030b58b0b6a07fa490db1748d2bd1586fb23398c4b7f56fadb));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x23076761fcaba77abb7e0463e69d289fa60ea8ac837a6ac98e5d212ccde67243), uint256(0x1d5efbfdabe047dd548a63fe7a5bae55a010c2c8315db9c855c414a0b94ecc1d));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x11863e53b5409570588df83a8da0a8ded50529fa6f003b3f5713be554926c7d7), uint256(0x06707d7c862410058e29110410642716ed83b3bd5dc55b2de31b5adb1c64c3d5));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1aa3a3dabcf685002bbda2da894ee03b81160793622714d4b1e393607a0c8566), uint256(0x3024a319acac804fe20bc02cdd9cdf5a901d9eba96ba8aef50f5acde47cae253));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0987e0150041d2bee34bd85968d9e54e5d29b638f3200c1f902599a0908e2226), uint256(0x03bebe6a1ef846d2579c76ad779713bcac63036aecc4d3962f8eb0cd6f7cfeb5));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x25c9a69d80ef74aae9379e6cce3be45172186bb63ae21dcca8a05f156d4e552a), uint256(0x12e2bb42fa584adfcf5b8c5cbdb57ac753052657b47db446b97eb83a177b6f43));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x05b64d099b8733279a1a8ec0667356f7ae6bbd9acfee9e26607281c333fd6a69), uint256(0x09a93bf2196d8df0e007b0f684d34065995f4ffbf9eb58a743ce5bb58417c856));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1ea6a6777bc480ca8a78ab1ed4e9f79e5c8172146a856fc77743c70b43fbee26), uint256(0x18424013b27a1eaa35e13f8e7bd41a31b45776ec957a0ffff96f53249d2bfa12));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x304cfa0387f1b42753437fbe8b61fe5ffefaf2b591ff39428597b957dd468323), uint256(0x1ff0e581e315744bdcfde617bc5493b7a1f0cec70ea9e05295ab493811c9ab82));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x23f5fb3d99055b52d5031836ad4689cd91dada0237470d83b2b3682993352db2), uint256(0x0d9a06e5b7dd800f471df3461e8c15c59e21b94a6ecc6558067c55ef70b84ae2));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x18911c8850db1faf2c0591f44775aa4593b3968cdcb6e90877aa2d21ac4b6799), uint256(0x1d2ceb1ac1cfc2cbed7998f36a82e9f499ce9c53c72bcaa13e432f545b227a5b));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x29cbb5574452f79a24fedd8219596da4fffbf81e54ddb3269a253dfb093656d9), uint256(0x12f2eae805ef694e922622a60af04c218bc4b67d9e473f0a24679e64cbc43a75));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x00fcdf831f0eb8605dd56077346813eb3b7def161102b2751e52216ac62077ec), uint256(0x207e35333bac7abc47286807b41c767bef699055c955e50ce3e91c9920e40932));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x005379a02a3b0eda7bae1ec09ea62ea311427e66ea48943a307030b07be30de4), uint256(0x17fbf25f90dd24c0f8ab1712e31e1c68d513d210a9d20b4591ef6252c35baec4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x27af371ce591a576bdcc16825063b347e121e2342d6fb0e6c9e2b929b8c1ef10), uint256(0x2f30368befa0b43e41d697e2e9dffc34035f341ded9a96a5be9b14b7c7d9bdfd));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2937be116856a2125c0576f79fc723fd884712c98d2efdcd7b4769fa366f4155), uint256(0x0e688fd18131d503fa6ee7ae2ee1de02cf15821bd4e45077b9e9c1f68c77093c));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0ea4b9751ad7f4ed62f2759f63f42ede2cc3397d30bf7da8681df2a54019c5ae), uint256(0x13dd974add5a114002e692428ef7e735da80fa28c7fb8cb3cddf7bc31b0921d4));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x21e8e88d600f5e0ad747910311b77cddd3f3e768c62aeeacc93d5b63bbeb87c8), uint256(0x2f9c2239d33511a736489db7e7d8d40e4f48e2fb55797e99158f40c34135d48d));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x12a6d560ea6dea23228b54cc6a6041e861320550baf135dd6b5cdec07dc30c9b), uint256(0x0614200c44f3ca8c07335ee5be39251384b06272eacdfee29ac2fc01a5406f90));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x10ed20c563f76cb505f7be2831941fcc661d3f78c8df65252a0a9b6c4162b888), uint256(0x1098b5722fae435a1a80d716054c2b8f05e4983d2d977038db324368bd089cc0));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x02a91a300e3ed84d71046dbb026575ac7d1ad333ef4914156f4054b36076d0d0), uint256(0x2671871a6bb81ae3396c545b101b36c05b7b714e61455dba78cc386a3745d625));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2a32f1649d499afd954baa45b987c4be92344f4d2512b118a4e2f156000ae63c), uint256(0x18074a599af9cd0a85af79c05f3aca0de6448672dd53fd14c204a1b8b84be121));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x12cfa8842c34edbc8f7fc6c176728a217f2c21e12fe8e336176870b5e3cdad3c), uint256(0x303e6ec2eefa3030c4f380378d1801684c616880b4a540302e485c8a514efac4));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x10e5416cfe9e81eb6b5534f4df37fc31a56c4247aa0b7a8cce0d55487fc492a9), uint256(0x02f7d738d3853bac1b98e98dae3cc9d3fa559be2929056247d335383deee04f8));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2b00c2d291883a19aba6e739e3de00164d5076efa76ac6eb860b5565b55af3b3), uint256(0x10020f21aee4ca564c57afebddd36adcec9cf0e6cb0d7267a72216fb0376bfc0));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x248a13a816682cb110d526f41b008366dd5fac1fa71f795f6ddbd6a5626d640f), uint256(0x12690f5e0e7b389edb6e70d0b511ac933d71c87ccb93656a6770557ce4011234));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x139ea694356125a63f7c54d300d7f68e5a1a9f8285c37c62ba56c67b73d83c26), uint256(0x1382e7da8e10377de21c1b4957a09edf701e6d1bd9b0bbc205794f62e06929f4));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1317d2f5f459c45f149665e82443cc997a6da0ad5050d1e3e1f3342f008d11f0), uint256(0x024b49041c57306fcd83bd9ed37c74e9ac26a9eaad2ae6f2c0441780ea899fca));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0406a08fa28e3a16951d88b89c98781a2f9c8e3716662e1b4c94735a113fc092), uint256(0x1104c42ae909890c8f5c42676d3dbd6cacb047762dbb5495392054c9c262f991));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1d47d644a8792519a9008212fc05e2a93d45b03fbd157e815d65e4b2a28e7c13), uint256(0x2b16fa3a7ae7a5d97908894dc3c94c74b5f6aad7f5a03750e7200a1e54df1d7f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x19d2b4bf06168d4b28fbb566dc405d42b4f7499f9de01e90a26a32e3adb07e99), uint256(0x1d5f3079264132ad2d4488b7295fa5a7a2c9a7d2759d3dc53bdae5913768cb0b));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x14d3fa353b9f4c983652eaf2c7bdd3077b001b06d7c4b49453b9e4428397d228), uint256(0x26073d6a344998f98bff3cdd6ac3cdad879e0f8b84d93a8f32f7d4a64f6b8f60));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x248245a20bbe0099ee2c6652134e66cbc30cc63cc5cb5bf3f57922c674eac411), uint256(0x04581a1709e329a1f949d733e3380e85f9dd77a07c691ef21a2f7de55fc1cc9f));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x062bff12b9156cf864f8af631b0d308ea65667bcff6fd8fc673533fda98f73e5), uint256(0x1babd3b2fb929fdbacf29047615ed9ccbf15fb3fa883f75aa7af768a679df1fe));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0d3d93ca87a0a3761bd55218129b3e910aff6dbba0556a4041df213b5c271a9a), uint256(0x10ad2e55b7cbb7c5161489450c5a65c3dbaa9a9254cc767ca24b901406d48b8a));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x27bd5d12e0266e7908a7691819ab8f3d8959fe00716b05ef10c6de5941f40586), uint256(0x2aeacaa9ae0d491cd48e08ac00661d482d01e2699ddbd441cbb7f32cdb081c4f));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x282e1917ce749358a0d271b70c979b8b90460c0440838f027e0e985e4731ad37), uint256(0x18779c35166cf892b7d8dc3589e8f2e086699082490229d7e0855039094108e7));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x13f605e4fbea8c481877fa84029c56b9fa4f86b97c9a54acea1645c6e06f743e), uint256(0x1b364e38cd6c587e00c9089311b266fd7b4b14d20e8d462ff17300a2008948f4));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x031cd7c66da9aeca385cc2047e7a28c56dd86c741a95af3339a755204fa42855), uint256(0x291ccb1a7cbd0922c6332613be91dc0152f8432c568cf467088c8c02430c1d0b));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x178351716cf50babd88745b0f9d97a8997caf703e2f50e32b41256d9c05e4cfc), uint256(0x16357ef77cc8c1e45ebfa690129c43fe611450302ad66e171965a0caf8be088e));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2c899adb015478d3b8d64f06710637e1a788af8da550a4f8b793a9a4c27e545e), uint256(0x1c4d4b33e42e6ccde3621ebf7d4c4d1323f887afa574a5a7fb4d27c75bfb5447));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2447cb9c1396cdee36bf2b3f4d5b1f060be4d3294a0c72845c4fe17cccee34ec), uint256(0x0b88897682a862e8f2f094600f4579d57a62f1d2a9eee43524c53dc2865d8965));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0b57061f6a92806e636e9e46214f37300ab644d5a55cd6bf8f34f366e2a84d17), uint256(0x0ec87ecb054e73af8b8fe6d88f1c6812a74a85d7d9103f76bc76fc398a9f6410));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x10ab83f8d526a238ecbf6be9ab3e4e6ba6a1b330a1bef3beba2227144f6c2193), uint256(0x095d59f933be7d90a0ff3ea4e2a3661799e0c3e490c1249defdde30e0a1e013f));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1730d5ea74767a7442ea8eb2f9738de843208c289388ba6ac116e7d98db8df09), uint256(0x1df25e4b9af4ed208be7c3660d70d0aa618bf0a3b382fda5d4fdbdae46c0ebe6));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x302cc83ac600f8c090f28696ea360261f929f170ef085578e5fa02b73e4662e6), uint256(0x08056a2cfb759642c8112d010aa79e8c2118b52d4342682c86e02bb8a088183c));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0c4a0dd6a63feee6a7e23cf5dd56f7ef1630f87ea2a6d485e1b511727311b23e), uint256(0x2595691a4f6b005d604de645a98bc701270b8b1b1bb07d25f0c6c32e8395ba1e));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x06d0f56794054932be0375882f04e4d7e704ad7359021d19a45974dacfe40362), uint256(0x1d095fa34545e57137f1717ef01bf80004e2405c6fddc004ffb46db6e7dbcce6));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0e46b24e1d70b0cfd1006ed5114344773bbc37a97ccde51c46005b01c047ba71), uint256(0x2c2928bfe04a243e4d0229bd3d1901fe023ca9583afeb17b342e2cf93d934e77));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x104806de15f8579fbcab7b9475a40534ebabff9b13f28ee81b5e736aabda8811), uint256(0x06e59f0d4120299f4ce7dbad3bc382d16f507dcf9ee7f3e04fd87d01a94281d8));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1332322226bd89ddc4c52810370355c3291d97e954f35542c990ffb24802e8f5), uint256(0x108651879a8f80e3fe10852f6848c8e6c34d9094f7459ed3bfd72837a454c869));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2d289958e323e8c62e9243c75e490464113ad062f6537c9263c9b18dd4b82d19), uint256(0x0ef2de4cd7f95664bf4efb0e2ca91de1fa286045367e1518bdb9c3e778d1a1c5));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x138a52d384940ad1f7cd06c754b4bfb36e80af97da34e5c462c605159d3dba07), uint256(0x0ad70f2772dc1e5045f94c77443ddd03d9173e4f7926441a9a92ac8e304291d0));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1fdffd2db51d396aea1405ad402a44ada48344968d841cf0edbd1cf85cbfe3ed), uint256(0x0976e3321246bba18899243fc034dc9676882d1e225564f9d005ffae446f8c6b));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0fb24d9b535d52d33c77da196abef75e8cf09cd5e9136ae4a126cdd2d34dd7ea), uint256(0x2d48b7fe4483ed94ea7d9290b087481ef0265c02547fd323bb290fd377c2103e));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x04d4b1a735b2fc11fe0a7b988f0f3c56653d5bf676527fe110b48fa2271a39fa), uint256(0x05fd3fe61ae8716bb063f6e333432381ca486be68455f39e10d725e5d55cd2cd));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0eaca13e67547b54a9742ebc28639de48621bf0da2c3efdffc7d7dad0cdcf764), uint256(0x1794e592c90eec1b1235a473612db34b2a77b4ace3f6defb7c6ab2353c52b487));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1e8f18adcc69f33b68969e9e3b67c3eda4c0743c5a440c156d6a0e5bbe05b849), uint256(0x01a9b9107e0bf4bde6d83f9efcebe431f1fc149a052bc18f05a94e2e2f7bdfa7));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x13e6326962debdf4e536df8e2574ae842ab92348902995513f22f56fe5b536e8), uint256(0x00b3cc47957f2f2f57ca70575e3a8f77f46e3ed3548c8d6bdadc1c542450860f));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x16463ec4be7926f3631c3a47940b1407a03e28c2f092f930bb64810b317a1275), uint256(0x255d56ed4898ae076640220e4c27433d6bca194285cae3e47c689d18bc62a277));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x23e29fc1fa6f463982d0a24b25ba6d4344d07c55a7075f63bf4627ea9eda8df5), uint256(0x140dec5fe742c62c0ff9e98b9838e7ae3de526072192347482af55f1a7f6b5e3));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x00d585abf6fea7129a11108676554efc57ce0c84e7d7b5ea54fbdd733f52c2ba), uint256(0x098f985aab15cce74a7da4096f52983499460a3685e2ff8042e0288ca8c009d4));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x09295b4540e6d3c338a3d68f4777cdb67fdac4fddc2b7d0218dc0ddfdf34c431), uint256(0x015394dc9804c5157cc1095b5c85dab580a2ab53751404bbad57b6ecb103acb1));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x21b9ba4616b7a382541d5f80530e2acc3072c5328d8848ad75bcbcf1493134ee), uint256(0x0c9191f1f22bad0a812613106e7097c836c3404711eaf3a3dca9b7196845d891));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0a74dd8baf31bd84bd8f29ceffe3263fa0193c2a6b71bb1f404a3dcc6c8bc672), uint256(0x0bb4dfa8ca60dd19eac850df113285893bd2e121a0ce2ccec2c530f3da83cb57));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x28a0f739f8a8d8ef3ea927fcb91edc8a8ee249c55426f4b6e3115d5a8d0ff209), uint256(0x26f6422a013acdc8322c90b5c898ddc4689cd204902170fe016f92ef65bde494));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x05e00201fdff5e35b89caec3b62b1814cb2a2937163374f355c0035f6a34c166), uint256(0x07b09d7ad82d7736525362303cd1630dc04c10ce79bcc7c7c457c8bab1f1cc69));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0718c8fa4f729030d03a287750b1976db45f0e3437213fa755d9d654da1c9e3c), uint256(0x1df090eeab345323d7bb64b18ecc624ecf9ed4d4a14fe3117ac9feb441dcf44a));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2f49c9863b754008edb6f612715d0334a6c376d14b7f4db80bc4f3e8ecbc22ab), uint256(0x1ace682800d76a3b1a1c479daebb9d96caba0a6974af10fd7f6301e085f90116));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0906a155ddde84e0a35389b69601e4dad3fbf06ccb2e37dc71fc37f2b45e0a40), uint256(0x15a1e2bc394590c9119c9e27e49ba1c03bc33deaee8dff6b927ee62f93c4831b));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x15d743f16287a1934d05564d56eeab7df7eb1132bf1515f140d7b49bf1fb9a98), uint256(0x2bbefe5b861f4a6ba73724b62730cc0fa899965c3acb2e897c3334529e78370f));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2c5b8bd329ed4ca887fd2db2e1a09057c9564a90cd704f04eeb60d55d1a4ee36), uint256(0x2c3fb24f17804f2b02a487f84b2a30e0f428059a49effe380d409847868613f7));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x25b2c682286f1868e673c0949e64304776145e5c0fc75a060fbc32c4f15ba80a), uint256(0x292411f569f8e5c9b29b3952892a7f43a781a0064b40365c37f5e0629b303879));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x109e5031466527efe99359b114600c63977f87ad557a5c45226b62396623fdc3), uint256(0x23d178c80849598c49c893b54a589c3acc1b4477ab3995d1936744225763eac6));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2e1c614001b2cb74c526a2bdd4c1e8b1d0230a29995f8934e330d97e560ca850), uint256(0x291a3fc413cad6f6f6cc25c31db28383252d220e220294bef0660699ef7c323d));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x08dc50ce1a82f53077d0e053c5ebe04dac2b2ae2c446fa2a70daf3ebcb51035f), uint256(0x21eb8a42aa205d7363ca7dd81614fcc6ca10d9ccd4250b132232eca0b1dc56c7));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x041a9e1e244e39200f665bc53acbbe64080ecd2dede024aa38360e9ff71ee649), uint256(0x0b7942f5f7b1f7f96dbbfb584d7bfebf2a2ea5a27340ee4c488d0f0779a91c96));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1813a833c9779507cc2624267375353dcadece22020961142cc8e4f3bfc4567f), uint256(0x18f7e2531588e148f0a721f65ed55e4e96305027887c333517411113cdc2e8be));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x2feaf1d1c9b473912ac306f22a99931f0365bde6893d0bf07701ec34286d6809), uint256(0x116942918309a38cdbad1b9f0acc03cd004a952f4ef20b7859a5f2df7e5ff86b));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x22533c3cdbc795f86d2cecb749de7dac69fbeee4b35d46f171c20e9dbe39f64f), uint256(0x2461d65b04ae4f54f796c44f8a73abf71d4b364216b55c85d2013c6a227539d3));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x05bc61a1bd34fb96c42b2eb676b300673196571ffc5e96e6fe21934d13b6ff9a), uint256(0x1a67a61a0405cfcaa8658041f7c9eb45ee4ed3dfcc6d2cd1eb79f91d5c04da27));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x13fe30a086d0b98944938a3dedd11f9f26df101832e76690feddf221b9c21eef), uint256(0x12f3e3e49c3d55e235f521c7a55a7501b8d8798f070eee2bbb2f1b48847f2317));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x097c822f155d17a46abcda1f9e477d63adc967ef76d1e743348b057fd578f642), uint256(0x0375b9cb55046117cecc7c010daf94a0d046d1fe9e2e3903712b7cb5bc05b690));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x1efeae4fef3bdfa05043b1c80b2a61c70a29e9ff4bcc5f745f52d2f50ef7e976), uint256(0x2cf468863189ad148e356897f9c87c36c93e8643a4b73ee1256931c39a18e0d0));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x23030a456217ec8b09e08d4c8b7fbfc9b16f0ebd19fdb999d58bc353bacfbb65), uint256(0x05c8ef6c132c6e63f19560f1bb10454c9c77c88b48b1ce176d364b60b42b5ea1));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x29282f14177ee6c864ff532556f2ab39fae62af59827b333b18f85f338273bb5), uint256(0x25b062bc07427b68ffd10c382adb7ad2a0114cbbd5c53de16845cdf39c5a9928));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x0c009a910c42f03f7c73b58969147043c4b730a769a1242ced4f98d9272c0a94), uint256(0x13dc80a2f01642e5fba93873416832ed81793043b05e26282214aa8be47ab7dc));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x26f02e46f3293b239b961a350ab7274b91f32026586202740a0a5f3187185517), uint256(0x07b2ab44112b27742c7a3c15475ac36bd0ed563f90688e2793704f18e5cba056));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x1472e9336562a622d95bf865958237a2d7e0e4e805f01e9c751c997430cbed56), uint256(0x05198a077fbf7db0f7b128ba4824f9895895a068774d08cfa9233c44550a37e4));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0587b7925730dbf28a006733b6e644ed602f6750b7e68701837e21dd0484da7f), uint256(0x1653bc15bf64751df166caf698d9adc45af19f295a7bf47d97778643013abfdf));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x140bf5f09ded863418466f9b22b2fccce4e3f2c054d72374351086e9c197e50d), uint256(0x2509a2a6a854c68ba63eaf57f039329ae310f3a2bdd0511b1f3677f3fe6c4a25));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x251a20bc144c73bef3698b4b628db9a96d9e4223057f4caed2a452891cf489ef), uint256(0x05b437cc360891072556460cc47137b122da8920bb616ff259ce616916e7f5db));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x229c9f386d463347f8ba5312ad235a2c0eafe7e8ae9a942aedb06340fbd2f7a7), uint256(0x0720131c47466c9919b6f47e362f326058cc9229039697ce1d9e54cf7dda46ef));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x18293a2662183f13d3c99f4f2ab49e76218dba1c8448c2d7b455ecc4f2eb7fbb), uint256(0x1b7355215258439f673dc0a21de97ca372ea8d206d6ecc53e3860092ab521f47));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1e14b90e173efac2a2a63e9f41773d41f060c6d3f0ec699616b31d532420ce56), uint256(0x2800c2ea8146aeb4ba22ac31b62499e6ca26b074cd0f4c1320db0a55bff32a7c));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x155169dd167b8d4712fd0a9c78c39d0e853f134973f31846819482751a1821e9), uint256(0x08f6d73bcc3f3832f72c1fd2f73a1b09de3af4d08b0374e06b5077facb7c5d63));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x040eacf73830093a0b74bde0d6f8a30e5f399a1338196b3d397e1ab1bb89acc2), uint256(0x253e34fe03dd84823699250ba406116680169819ae87b70ede6eea2c5bd0a1ae));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x1735b63753c20459cb081f7043de3f0d02dffa576b799a9b72aa753444f96d9f), uint256(0x15985c56c592f7fe884db3e0ca3d0f0f96d288f72e02e77958e85ecd54e907da));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x211d4c7c11e607ba6857b5e834ecc802889c53bc8d0166148ee2b0e2c3d5e89b), uint256(0x2091d301ace574484e0ffe90fda2e040173234efdeb833a18eccdb1cb1450731));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x11f3e33f4bb02134c26a78d1989c0c657a9bc6d2be0931d315f28380656eaf24), uint256(0x0cbdbff5e4d62cae9f72a4fc5244754f7ebdf09a9af0800a1dc28d1def27befe));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0c9d23b41e0d5680420d2912e5097b2bf8fa24d25f4c2bef6a21d4fcc2e9a028), uint256(0x0e4278ca8acaf1f07ee9fb4f0f7ba678e0dc221c87250dce6a45abba95c17909));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x2da242092586ebb23424546befbfed6ebc3f8136d48bdb2a73dc3213baf3c98c), uint256(0x2049d39d173ef2de2bcc2be2b754ee68547081621235e6ff3665b61753acb535));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x09266a87dce4258cde99c3e680a178c6bb518c24b20e8ba484ad8e157488a64d), uint256(0x25eca8ca48592b8f0ea1201c965f2f3be07e743c8653c962d37a671d5ed29743));
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
            Proof memory proof, uint[108] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](108);
        
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
