// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "db.h"
#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
	(0, hashGenesisBlockOfficial )
(100, uint256("0x000001c5de5cbc95441c21531a8c82a6e1d64568abd1ab9d692ba80783cfd25a"))
(200, uint256("0x0000047588e1099b107625dfa7003446b13319b0f5abe767eebdf7b93bbff3f0"))
(500, uint256("0x0000012dffdffa92f8c4fa0e5a6da12dba07253a7e2647919db01fff46eb7b7b"))
(1000, uint256("0x000003b1930dc9a9fbfa287d9c5cc3fc8e383917e442a1f548773f2b1cf4a1ff"))
(1500, uint256("0x22ae9f45e33a45315ba3ecf1a2fbd5076f830c35486716751c7b7e57add2dcd5"))
(3000, uint256("0x525294a29e76c4eb145c10d6abf6b11b95c5499648b2fe8c8f828b5f4de31ff2"))
(3500, uint256("0x000002c91d4171eba9e97dcb2e6ca4fd0ccc3f44a3cf4904e7c61d9072dd635f"))
(3740, uint256("0x00000616b495999043462aef9ca671105431aec86112a63568ecd8ef4bac7fac"))
(10000, uint256("0xc0a885e906628cf21bec555e6e6d879f009a0c78862bf4e68ddfe9df176a340a"))
(15000, uint256("0x922e4de52f0edfd5a4615994f6c1f6e7fee76e44f32cac48d9fb5770d0f98ed3"))
(20000, uint256("0x880a5898406b7026259c237ad3172f5e2a1ec2d90009e5a5d96bfab9e958af75"))
(25000, uint256("0x7c737e20cbc809306861af335ba103f76bc602e4612388d5fd4fa00be8e19be9"))
(30000, uint256("0xc1987f2c4741b93b67b70389a38ee80fb980cb5d1bd63e3e27d2d78722f51296"))
(35000, uint256("0xac4ef0779fb50a9f8997af7b4f33d08ef3d6f3f6b99414ec5418eb020d80f6dd"))
(40000, uint256("0x9f7a928c4585ef80af4f292713a7e993290328e7011fe229d7f9a27a1998dbd3"))
(45000, uint256("0x626ec85a4bd28045bfd931f57f1b7b7a2aa29ebe6db7388d0e551433f408e16f"))
(50000, uint256("0xa53e431d23d124aac60997b94b3ff5fc67bd46eb75876527e37f99bbaff7115d"))
(55000, uint256("0xd7acdff4e3494e80cce1b0790570b6efaba8a1cc90ec53b52c83b091dea1f9d6"))
(60000, uint256("0x59be68d465303e469edbf74c9ddc38c1481caf799fb52a25b02819bffdd84941"))
(65000, uint256("0x5a464a3788eac75cb7a506346721352161a51817bcae182fc955a23b0ba61e18"))
(70000, uint256("0x658b88e70b7c7763520303a8cd5ace402cb39ce06b18545db9c7bbbf15903122"))
(75000, uint256("0x44db74a808af8487bc69a132c8cfe5ececec125d6692876e05eecbf125c3181b"))
(80000, uint256("0x88aeb9cb77778ec461cbcdbb9d29db6d93a938638ab3ab54871de78f438d43bd"))
(85000, uint256("0x5d0d6e30695a75559ea2e143198b5850e82e56689593b96ba093c4c7bf0e9e5e"))
(90000, uint256("0x121d05685b2eebfb67f963be7a0df278273ed5b46d3a44c22dd231a8c76b892a"))
(95000, uint256("0x029171a33570535bef40d589b775c13eee486482f53b10de5b55675da0af453c"))
(100000, uint256("0x74ff532f67e60492dd2e29ee13e99543f551a8abbd92ca3a9324528539777680"))
(105000, uint256("0x55c393c1a3c008741a48f2a2469d861c159d2e82ddedc457842e91d76eae574a"))
(110000, uint256("0x5dc1513e962ebfa3f18c50a8f2717b9a75274c39374796848778ca2e8825669a"))
(115000, uint256("0xc392fe08e51429307763c163d6fd95c8622f4c98d83520d75f95a6ef9c74f0ed"))
(120000, uint256("0x9f647c81e0093cfb196dd831c059e888744eac3b1445b9f1eaf2563bcf081eba"))
(125000, uint256("0x1c8295ef8e67f407e422888e87defdcc90f679283a8c6d612f8e030c8e39227e"))
(130000, uint256("0x807e552773402840876899d4752fa139e68d5f808877ab241a2fe04560efb464"))
(135000, uint256("0xeb573a1e347f32a8cacfbdfe2b6902200b5a5b0a61ad3024895e4b2663298c35"))
(140000, uint256("0xcaef9391176fde753b53c5f7fb3a28606cc69a845a4ae4d0b84246fee3bd78e5"))
(145000, uint256("0x5195b19ed46a4c6531c10284615be5b33cac6fe2fdcaa0540deee7aa39138f16"))
(150000, uint256("0xb1b56d549dd735175d757a00875c3fd52cd0279b7e20451361f6e0ffb0d1a3b9"))
(155000, uint256("0x22d311efd3df637e16ceaab99841c5827adad79657fe0ef2ed6f7ed8557ebcb5"))
(160000, uint256("0x505df09c1b042c09991e39246289ae6f44626ed2ce946f11cc4d4aa01aee3256"))
(165000, uint256("0xef0903f8b4bc64339b7b9f31bb7908c6ac502f2ca10868ab62af5d7741260a42"))
(170000, uint256("0x80bf46cb020a7bf3fd79eabb14cd6d82454cefa9ce73918196024bffe743d981"))
(175000, uint256("0x2d4bcb741d1b225cff43a292d78c0b416b3493448397221d5bd0be90ddffe8b1"))
(180000, uint256("0xdad2cc23f2fa0ae1c78207c7932a54bfd3a6175f307f1a126fe6ebfe9efec6ce"))
(185000, uint256("0xe7bc8614272fcc98a5d8d0ec0058ab48e87c355f06aa5258674c68caaf6c27b2"))
(190000, uint256("0xf6b0e26e5a21be8a753e984fae25bcd086a9b3610312afef2b33f297ceb59d8f"))
(195000, uint256("0xdfd4897d0bd81d96fe6e528ce2e846696a126575a40112cd92021a1409ef8264"))
(200000, uint256("0x1e80e905a09e8ff83c8e39647bd9ba69849943e4e1e72c509537bbf0ac430f86"))
(205000, uint256("0x60d7bbd21a7019ff6bf5e53fc0e196d4c8ecdd8650bfacee42bd8cb1fe3f595a"))
(210000, uint256("0xd8fa89df4bd16b1e3f598bc78f4459473fdae3f813d9f6d41e54c2bb85958dc0"))
(215000, uint256("0xce10453e7da8abb2a7d2ebafe12d8602f94ccacab2e77dfe780841ebcc9fe085"))
(220000, uint256("0x5010855fd3cfcc88653b7e0bb4ad226378f44d3ddf54263d61290741c5371cdc"))
(225000, uint256("0x3bf5eae06f488fa47aab5063c336c1265274a76c7150cc12eda5de6aa94a3a39"))
(230000, uint256("0x35e56a41104f0a5b171dcc4eceae6ad927b6ea3f642cc5d5a7c5ec8e678daad9"))
(235000, uint256("0x737f2366a67e47e2454bfdfbebcda01c40bb79d011097a77d8dcd1258732ab13"))
(240000, uint256("0x001cdbafb87051e535fb135329e9b30154f3b77fdb43735597b972c995fd48e9"))
(245000, uint256("0x0d4ea43c15afac9aa1daa888b4b59ce1a3a754f1ad02b4b2b292d846c1986f70"))
(250000, uint256("0xe235837a44cc11451d713cb675ab899ff4c5350bf71f382a27b7a3398824f783"))
(255000, uint256("0x343f447e1696582f4f4a7be57c71be39f1a4cd99566201606b801a2f58df95c5"))
(260000, uint256("0xc511dd38d85fdec34e99814aaedba3c60acf237ff801dd4a061d78cef317a0d8"))
(265000, uint256("0x36302b6a89f89f6279cff994a00e724a014ebcf60d74770321a73552aad9b91a"))
(270000, uint256("0xd97ff5ee008b9f74457c6303b1e92ce0f2ee65a56b9b7471a9db7f5413498d2b"))
(275000, uint256("0x545b13b8e7392e0c85a848e7e0e37e1c22836408df190047e97d01f40e7173cf"))
(280000, uint256("0x8bd60abfd5017c5fddfc8837e82664924fcab82bb5fd83bc22735445626be0b0"))
(283000, uint256("0x8ecd86c186eb8cd3fd6ffb1ac9862dabece0412b3aca35c9e37a5d88dc9266a6"))
		;

    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, hashGenesisBlockTestNet )
        ;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // ppcoin: synchronized checkpoint (centrally broadcasted)
    uint256 hashSyncCheckpoint = 0;
    uint256 hashPendingCheckpoint = 0;
    CSyncCheckpoint checkpointMessage;
    CSyncCheckpoint checkpointMessagePending;
    uint256 hashInvalidCheckpoint = 0;
    CCriticalSection cs_hashSyncCheckpoint;

    // ppcoin: get last synchronized checkpoint
    CBlockIndex* GetLastSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            error("GetSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        else
            return mapBlockIndex[hashSyncCheckpoint];
        return NULL;
    }

    // ppcoin: only descendant of current sync-checkpoint is allowed
    bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
    {
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        if (!mapBlockIndex.count(hashCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());

        CBlockIndex* pindexSyncCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        CBlockIndex* pindexCheckpointRecv = mapBlockIndex[hashCheckpoint];

        if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight)
        {
            // Received an older checkpoint, trace back from current checkpoint
            // to the same height of the received checkpoint to verify
            // that current checkpoint should be a descendant block
            CBlockIndex* pindex = pindexSyncCheckpoint;
            while (pindex->nHeight > pindexCheckpointRecv->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("ValidateSyncCheckpoint: pprev1 null - block index structure failure");
            if (pindex->GetBlockHash() != hashCheckpoint)
            {
                hashInvalidCheckpoint = hashCheckpoint;
                return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
            }
            return false; // ignore older checkpoint
        }

        // Received checkpoint should be a descendant block of the current
        // checkpoint. Trace back to the same height of current checkpoint
        // to verify.
        CBlockIndex* pindex = pindexCheckpointRecv;
        while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");
        if (pindex->GetBlockHash() != hashSyncCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
        return true;
    }

    bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
    {
        CTxDB txdb;
        txdb.TxnBegin();
        if (!txdb.WriteSyncCheckpoint(hashCheckpoint))
        {
            txdb.TxnAbort();
            return error("WriteSyncCheckpoint(): failed to write to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
        if (!txdb.TxnCommit())
            return error("WriteSyncCheckpoint(): failed to commit to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
        txdb.Close();

        Checkpoints::hashSyncCheckpoint = hashCheckpoint;
        return true;
    }

    bool AcceptPendingSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint != 0 && mapBlockIndex.count(hashPendingCheckpoint))
        {
            if (!ValidateSyncCheckpoint(hashPendingCheckpoint))
            {
                hashPendingCheckpoint = 0;
                checkpointMessagePending.SetNull();
                return false;
            }

            CTxDB txdb;
            CBlockIndex* pindexCheckpoint = mapBlockIndex[hashPendingCheckpoint];
            if (!pindexCheckpoint->IsInMainChain())
            {
                CBlock block;
                if (!block.ReadFromDisk(pindexCheckpoint))
                    return error("AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                if (!block.SetBestChain(txdb, pindexCheckpoint))
                {
                    hashInvalidCheckpoint = hashPendingCheckpoint;
                    return error("AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                }
            }
            txdb.Close();

            if (!WriteSyncCheckpoint(hashPendingCheckpoint))
                return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
            hashPendingCheckpoint = 0;
            checkpointMessage = checkpointMessagePending;
            checkpointMessagePending.SetNull();
            printf("AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", hashSyncCheckpoint.ToString().c_str());
            // relay the checkpoint
            if (!checkpointMessage.IsNull())
            {
                BOOST_FOREACH(CNode* pnode, vNodes)
                    checkpointMessage.RelayTo(pnode);
            }
            return true;
        }
        return false;
    }

    // Automatically select a suitable sync-checkpoint 
    uint256 AutoSelectSyncCheckpoint()
    {
        // Proof-of-work blocks are immediately checkpointed
        // to defend against 51% attack which rejects other miners block 

        // Select the last proof-of-work block
        const CBlockIndex *pindex = GetLastBlockIndex(pindexBest, false);
        // Search forward for a block within max span and maturity window
        while (pindex->pnext && (pindex->GetBlockTime() + CHECKPOINT_MAX_SPAN <= pindexBest->GetBlockTime() || pindex->nHeight + std::min(6, nCoinbaseMaturity - 20) <= pindexBest->nHeight))
            pindex = pindex->pnext;
        return pindex->GetBlockHash();
    }

    // Check against synchronized checkpoint
    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev)
    {
        if (fTestNet) return true; // Testnet has no checkpoints
        int nHeight = pindexPrev->nHeight + 1;

        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];

        if (nHeight > pindexSync->nHeight)
        {
            // trace back to same height as sync-checkpoint
            const CBlockIndex* pindex = pindexPrev;
            while (pindex->nHeight > pindexSync->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("CheckSync: pprev null - block index structure failure");
            if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != hashSyncCheckpoint)
                return false; // only descendant of sync-checkpoint can pass check
        }
        if (nHeight == pindexSync->nHeight && hashBlock != hashSyncCheckpoint)
            return false; // same height with sync-checkpoint
        if (nHeight < pindexSync->nHeight && !mapBlockIndex.count(hashBlock))
            return false; // lower height than sync-checkpoint
        return true;
    }

    bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint == 0)
            return false;
        if (hashBlock == hashPendingCheckpoint)
            return true;
        if (mapOrphanBlocks.count(hashPendingCheckpoint) 
            && hashBlock == WantedByOrphan(mapOrphanBlocks[hashPendingCheckpoint]))
            return true;
        return false;
    }

    // ppcoin: reset synchronized checkpoint to last hardened checkpoint
    bool ResetSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        const uint256& hash = mapCheckpoints.rbegin()->second;
        if (mapBlockIndex.count(hash) && !mapBlockIndex[hash]->IsInMainChain())
        {
            // checkpoint block accepted but not yet in main chain
            printf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
            CTxDB txdb;
            CBlock block;
            if (!block.ReadFromDisk(mapBlockIndex[hash]))
                return error("ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
            if (!block.SetBestChain(txdb, mapBlockIndex[hash]))
            {
                return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
            }
            txdb.Close();
        }
        else if(!mapBlockIndex.count(hash))
        {
            // checkpoint block not yet accepted
            hashPendingCheckpoint = hash;
            checkpointMessagePending.SetNull();
            printf("ResetSyncCheckpoint: pending for sync-checkpoint %s\n", hashPendingCheckpoint.ToString().c_str());
        }

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
        {
            const uint256& hash = i.second;
            if (mapBlockIndex.count(hash) && mapBlockIndex[hash]->IsInMainChain())
            {
                if (!WriteSyncCheckpoint(hash))
                    return error("ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
                printf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n", hashSyncCheckpoint.ToString().c_str());
                return true;
            }
        }

        return false;
    }

    void AskForPendingSyncCheckpoint(CNode* pfrom)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) && (!mapOrphanBlocks.count(hashPendingCheckpoint)))
            pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
    }

    bool SetCheckpointPrivKey(std::string strPrivKey)
    {
        // Test signing a sync-checkpoint with genesis block
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = !fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        std::vector<unsigned char> vchPrivKey = ParseHex(strPrivKey);
        CKey key;
        key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return false;

        // Test signing successful, proceed
        CSyncCheckpoint::strMasterPrivKey = strPrivKey;
        return true;
    }

    bool SendSyncCheckpoint(uint256 hashCheckpoint)
    {
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = hashCheckpoint;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        if (CSyncCheckpoint::strMasterPrivKey.empty())
            return error("SendSyncCheckpoint: Checkpoint master key unavailable.");
        std::vector<unsigned char> vchPrivKey = ParseHex(CSyncCheckpoint::strMasterPrivKey);
        CKey key;
        key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

        if(!checkpoint.ProcessSyncCheckpoint(NULL))
        {
            printf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
            return false;
        }

        // Relay checkpoint
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
        return true;
    }

    // Is the sync-checkpoint outside maturity window?
    bool IsMatureSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (nBestHeight >= pindexSync->nHeight + nCoinbaseMaturity ||
                pindexSync->GetBlockTime() + nStakeMinAge < GetAdjustedTime());
    }

    // Is the sync-checkpoint too old?
    bool IsSyncCheckpointTooOld(unsigned int nSeconds)
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (pindexSync->GetBlockTime() + nSeconds < GetAdjustedTime());
    }
}

// ppcoin: sync-checkpoint master key
const std::string CSyncCheckpoint::strMasterPubKey = "04b8d49de838594c2289037043e5330f12f4cb98f0a2f0cda90a2a957c3358c95480bb6db13fd5a50368c1f24096495eb473be801e5c919b0668a2f7acf74ed291";

std::string CSyncCheckpoint::strMasterPrivKey = "";

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    CKey key;
    if (!key.SetPubKey(ParseHex(CSyncCheckpoint::strMasterPubKey)))
        return error("CSyncCheckpoint::CheckSignature() : SetPubKey failed");
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// ppcoin: process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{
    if (!CheckSignature())
        return false;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        printf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocks.count(hashCheckpoint)? WantedByOrphan(mapOrphanBlocks[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (!Checkpoints::ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CTxDB txdb;
    CBlockIndex* pindexCheckpoint = mapBlockIndex[hashCheckpoint];
    if (!pindexCheckpoint->IsInMainChain())
    {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (!block.ReadFromDisk(pindexCheckpoint))
            return error("ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        if (!block.SetBestChain(txdb, pindexCheckpoint))
        {
            Checkpoints::hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }
    txdb.Close();

    if (!Checkpoints::WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
