/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSATests.cpp

 Contains test cases to test the SLH-DSA class
 *****************************************************************************/

#include <stdlib.h>
#include <utility>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "SLHDSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAMechanismParam.h"
#include "SLHDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SLHDSATests);

static const std::vector<unsigned long> allParameterSets =
{
	CKP_SLH_DSA_SHA2_128S, CKP_SLH_DSA_SHAKE_128S, CKP_SLH_DSA_SHA2_128F, CKP_SLH_DSA_SHAKE_128F, CKP_SLH_DSA_SHA2_192S, CKP_SLH_DSA_SHAKE_192S, CKP_SLH_DSA_SHA2_192F, CKP_SLH_DSA_SHAKE_192F, CKP_SLH_DSA_SHA2_256S, CKP_SLH_DSA_SHAKE_256S, CKP_SLH_DSA_SHA2_256F, CKP_SLH_DSA_SHAKE_256F
};

// Pre-hash functions used with the SHA2 parameter sets in `allParameterSets`,
// as specified in the HashSLH-DSA OIDS.
static const std::vector<CK_MECHANISM_TYPE> allPreHashFunctions =
{
	CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA224, CKM_SHA512_224, CKM_SHA512_256, CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512
};


const std::pair<ByteString, size_t> getHashFunctionInfo(CK_MECHANISM_TYPE mechanismType) {
	std::string oidStr = std::string();
	size_t digestLen = 0;
	switch (mechanismType) {
		case CKM_SHA256: oidStr = std::string("0609608648016503040201"); digestLen = 32; break;
		case CKM_SHA384: oidStr = std::string("0609608648016503040202"); digestLen = 48; break;
		case CKM_SHA512: oidStr = std::string("0609608648016503040203"); digestLen = 64; break;
		case CKM_SHA224: oidStr = std::string("0609608648016503040204"); digestLen = 28; break;
		case CKM_SHA512_224: oidStr = std::string("0609608648016503040205"); digestLen = 28; break;
		case CKM_SHA512_256: oidStr = std::string("0609608648016503040206"); digestLen = 32; break;
		case CKM_SHA3_224: oidStr = std::string("0609608648016503040207"); digestLen = 28; break;
		case CKM_SHA3_256: oidStr = std::string("0609608648016503040208"); digestLen = 32; break;
		case CKM_SHA3_384: oidStr = std::string("0609608648016503040209"); digestLen = 48; break;
		case CKM_SHA3_512: oidStr = std::string("060960864801650304020A"); digestLen = 64; break;
	}
	ByteString oid ((const unsigned char*)oidStr.c_str(), oidStr.size());
	return std::pair<ByteString, size_t> (oid, digestLen);
}

SLHDSATests::SLHDSATests() : slhdsa(NULL)
{
}

void SLHDSATests::setUp()
{
	slhdsa = NULL;

	slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);

	// Check the SLHDSA object
	CPPUNIT_ASSERT(slhdsa != NULL);
}

void SLHDSATests::tearDown()
{
	if (slhdsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
	}

	fflush(stdout);
}

void SLHDSATests::testKeyGeneration()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Set domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		p->setParameterSet(parameterSet);

		// Generate key-pair
		AsymmetricKeyPair *kp;
		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

		SLHDSAPublicKey *pub = (SLHDSAPublicKey *)kp->getPublicKey();
		SLHDSAPrivateKey *priv = (SLHDSAPrivateKey *)kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getParameterSet() == parameterSet);
		CPPUNIT_ASSERT(priv->getParameterSet() == parameterSet);

		slhdsa->recycleParameters(p);
		slhdsa->recycleKeyPair(kp);
	}
}

void SLHDSATests::testSerialisation()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		p->setParameterSet(parameterSet);

		// Serialise the parameters
		ByteString serialisedParams = p->serialise();

		// Deserialise the parameters
		AsymmetricParameters *dSLHDSA;

		CPPUNIT_ASSERT(slhdsa->reconstructParameters(&dSLHDSA, serialisedParams));

		CPPUNIT_ASSERT(dSLHDSA->areOfType(SLHDSAParameters::type));

		SLHDSAParameters *ddSLHDSA = (SLHDSAParameters *)dSLHDSA;

		CPPUNIT_ASSERT(p->getParameterSet() == ddSLHDSA->getParameterSet());

		// Generate a key-pair
		AsymmetricKeyPair *kp;

		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, dSLHDSA));


		// Serialise the key-pair
		ByteString serialisedKP = kp->serialise();

		// Deserialise the key-pair

		AsymmetricKeyPair *dKP;

		CPPUNIT_ASSERT(slhdsa->reconstructKeyPair(&dKP, serialisedKP));

		// Check the deserialised key-pair
		SLHDSAPrivateKey *privKey = (SLHDSAPrivateKey *)kp->getPrivateKey();
		SLHDSAPublicKey *pubKey = (SLHDSAPublicKey *)kp->getPublicKey();

		SLHDSAPrivateKey *dPrivKey = (SLHDSAPrivateKey *)dKP->getPrivateKey();
		SLHDSAPublicKey *dPubKey = (SLHDSAPublicKey *)dKP->getPublicKey();

		CPPUNIT_ASSERT(privKey->getParameterSet() == dPrivKey->getParameterSet());
		CPPUNIT_ASSERT(privKey->getValue() == dPrivKey->getValue());

		CPPUNIT_ASSERT(pubKey->getParameterSet() == dPubKey->getParameterSet());
		CPPUNIT_ASSERT(pubKey->getValue() == dPubKey->getValue());

		slhdsa->recycleParameters(p);
		slhdsa->recycleParameters(dSLHDSA);
		slhdsa->recycleKeyPair(kp);
		slhdsa->recycleKeyPair(dKP);
	}
}

void SLHDSATests::testPKCS8()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		p->setParameterSet(parameterSet);

		// Generate a key-pair
		AsymmetricKeyPair *kp;

		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		SLHDSAPrivateKey *priv = (SLHDSAPrivateKey *)kp->getPrivateKey();
		CPPUNIT_ASSERT(priv != NULL);

		SLHDSAPublicKey *pub = (SLHDSAPublicKey *)kp->getPublicKey();
		CPPUNIT_ASSERT(pub != NULL);

		// Encode and decode the private key
		ByteString pkcs8 = priv->PKCS8Encode();
		CPPUNIT_ASSERT(pkcs8.size() != 0);

		SLHDSAPrivateKey *dPriv = (SLHDSAPrivateKey *)slhdsa->newPrivateKey();
		CPPUNIT_ASSERT(dPriv != NULL);

		CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

		CPPUNIT_ASSERT(priv->getParameterSet() == dPriv->getParameterSet());
		CPPUNIT_ASSERT(priv->getValue() == dPriv->getValue());

		slhdsa->recycleParameters(p);
		slhdsa->recyclePrivateKey(dPriv);
		slhdsa->recycleKeyPair(kp);
	}
}

void SLHDSATests::testSigningVerifying()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		CPPUNIT_ASSERT(p != NULL);
		p->setParameterSet(parameterSet);

		// Generate key-pair
		AsymmetricKeyPair *kp;
		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

		// Generate some data to sign
		ByteString dataToSign;

		RNG *rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		// Sign the data
		ByteString sig;
		CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA));

		// And verify it
		CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA));

		slhdsa->recycleKeyPair(kp);
		slhdsa->recycleParameters(p);
	}
}

void SLHDSATests::testSigningVerifyingPreHashed()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		for (const CK_MECHANISM_TYPE hashFunction: allPreHashFunctions) {
			// Get domain parameters
			SLHDSAParameters *p = new SLHDSAParameters();
			CPPUNIT_ASSERT(p != NULL);
			p->setParameterSet(parameterSet);

			// Generate key-pair
			AsymmetricKeyPair *kp;
			CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

			// Get the pre-hash function parameters
			const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(hashFunction);
			const ByteString oid = hashFunctionInfo.first;
			const size_t digestLen = hashFunctionInfo.second;
			SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, oid, digestLen);

			// Generate some data to sign
			ByteString dataToSign;

			RNG *rng = CryptoFactory::i()->getRNG();
			CPPUNIT_ASSERT(rng != NULL);

			CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

			// Sign the data
			ByteString sig;
			CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

			// And verify it
			CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

			slhdsa->recycleKeyPair(kp);
			slhdsa->recycleParameters(p);
		}
	}
}

void SLHDSATests::testSigningVerifyingHedgePreferred()
{

	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgePreferredWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_PREFERRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgePreferredWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT_EQUAL(false, slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgePreferredPreHashed()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgePreferredPreHashedWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	std::string contextStr = std::string("HEDGE_PREFERRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, contextBS, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgePreferredPreHashedWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	std::string contextStr = std::string("HEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, contextBS, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgeRequired()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgeRequiredWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgeRequiredWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgeRequiredPreHashed()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgeRequiredPreHashedWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	std::string contextStr = std::string("HEDGE_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, contextBS, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingHedgeRequiredPreHashedWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	std::string contextStr = std::string("HEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, contextBS, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingDeterministic()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED);

	// Sign the data
	ByteString sig1;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	// Sign again and assert identical signature
	ByteString sig2;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig2, AsymMech::SLHDSA, &context));
	CPPUNIT_ASSERT(sig1 == sig2);

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingDeterministicWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("DETERMINISTIC_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, contextBS);

	// Sign the data
	ByteString sig1;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	// Sign again and assert identical signature
	ByteString sig2;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig2, AsymMech::SLHDSA, &context));
	CPPUNIT_ASSERT(sig1 == sig2);

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingDeterministicWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("DETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingDeterministicPreHashed()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingDeterministicPreHashedWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	std::string contextStr = std::string("DETERMINISTIC_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, contextBS, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

void SLHDSATests::testSigningVerifyingDeterministicPreHashedWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Get the pre-hash function parameters
	const std::pair<ByteString, size_t> hashFunctionInfo = getHashFunctionInfo(CKM_SHA256);
	const ByteString oid = hashFunctionInfo.first;
	const size_t digestLen = hashFunctionInfo.second;
	std::string contextStr = std::string("DETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());
	SLHDSAMechanismParam params = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, contextBS, oid, digestLen);

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, digestLen));

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &params));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

#endif
