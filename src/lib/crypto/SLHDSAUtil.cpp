/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSAUtil.cpp

 SLH-DSA convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAUtil.h"
#include "SLHDSAMechanismParam.h"

/** \brief getSLHDSAPrivateKey */
/*static*/ CK_RV SLHDSAUtil::getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Private Key Attributes
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK || value.size() == 0)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
		if (value.size() == 0)
			return CKR_GENERAL_ERROR;
	}

	if (!key->attributeExists(CKA_PARAMETER_SET))
	{
		privateKey->setParameterSet(0);
		ERROR_MSG("CKA_PARAMETER_SET attribute is missing");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	unsigned long parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, 0);
	if (!SLHDSAParameters::isSupported(parameterSet))
	{
		ERROR_MSG("Invalid SLH-DSA parameter set ID");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	privateKey->setParameterSet(parameterSet);
	privateKey->setValue(value);

	return CKR_OK;
}

/** \brief getSLHDSAPublicKey */
/*static*/ CK_RV SLHDSAUtil::getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Public Key Attributes
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK || value.size() == 0)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
		if (value.size() == 0)
			return CKR_GENERAL_ERROR;
	}

	if (!key->attributeExists(CKA_PARAMETER_SET))
	{
		publicKey->setParameterSet(0);
		ERROR_MSG("CKA_PARAMETER_SET attribute is missing");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	unsigned long parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, 0);
	if (!SLHDSAParameters::isSupported(parameterSet))
	{
		ERROR_MSG("Invalid SLH-DSA parameter set ID");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	publicKey->setParameterSet(parameterSet);
	publicKey->setValue(value);

	return CKR_OK;
}

/** \brief setSLHDSAPrivateKey */
/*static*/ CK_RV SLHDSAUtil::setSLHDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate)
{
	if (key == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	AsymmetricAlgorithm* slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
	if (slhdsa == NULL)
	{
		return CKR_GENERAL_ERROR;
	}
	PrivateKey* priv = slhdsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_HOST_MEMORY;
	}
	if (!priv->PKCS8Decode(ber))
	{
		slhdsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	if (!priv->isOfType(SLHDSAPrivateKey::type))
	{
		slhdsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	// SLH-DSA Private Key Attributes
	ByteString value;
	if (isPrivate)
	{
		if (token == NULL)
		{
			slhdsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
			return CKR_ARGUMENTS_BAD;
		}
		if (!token->encrypt(((SLHDSAPrivateKey*)priv)->getValue(), value))
		{
			slhdsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		value = ((SLHDSAPrivateKey*)priv)->getValue();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PARAMETER_SET, ((SLHDSAPrivateKey*)priv)->getParameterSet());
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	slhdsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);

	return bOK ? CKR_OK : CKR_GENERAL_ERROR;
}

/** \brief setHedge */
/*static*/ CK_RV SLHDSAUtil::setHedge(CK_HEDGE_TYPE inHedgeType, Hedge::Type* outHedgeType)
{

	if (outHedgeType == NULL)
	{
		ERROR_MSG("Invalid parameters, outHedgeType is NULL");
		return CKR_ARGUMENTS_BAD;
	}

	Hedge::Type hedgeType = Hedge::HEDGE_PREFERRED;

	switch (inHedgeType)
	{
	case CKH_HEDGE_REQUIRED:
		hedgeType = Hedge::HEDGE_REQUIRED;
		break;
	case CKH_DETERMINISTIC_REQUIRED:
		hedgeType = Hedge::DETERMINISTIC_REQUIRED;
		break;
	case CKH_HEDGE_PREFERRED:
		// Per PKCS11v3.2 section 6.67.5
		// "If no parameter is supplied the hedgeVariant will be CKH_HEDGE_PREFERRED"
		hedgeType = Hedge::HEDGE_PREFERRED;
		break;
	default:
		ERROR_MSG("SLH-DSA: Invalid parameters, unknown hedgeVariant");
		return CKR_ARGUMENTS_BAD;
	}
	*outHedgeType = hedgeType;
	return CKR_OK;
}

/** \brief setHashOid */
/*static*/ CK_RV SLHDSAUtil::setHashOid(CK_MECHANISM_TYPE inHash, ByteString* outOid, size_t* outDigestLen) {
	if (outOid == NULL)
	{
		ERROR_MSG("Invalid parameters, outOid is NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (outDigestLen == NULL)
	{
		ERROR_MSG("Invalid parameters, outDigestLen is NULL");
		return CKR_ARGUMENTS_BAD;
	}

	unsigned char lastHashOidArc;
	size_t digestLen;

	// FIXME: This hard-codes the hash-function OIDs. Ideally, these should be fetched
	// from the relevant crypto backend (OpenSSL, Botan) instead.
	switch (inHash)
	{
	case CKM_SHA256:
		lastHashOidArc = 0x01;
		digestLen = 32;
		break;
	case CKM_SHA384:
		lastHashOidArc = 0x02;
		digestLen = 48;
		break;
	case CKM_SHA512:
		lastHashOidArc = 0x03;
		digestLen = 64;
		break;
	case CKM_SHA224:
		lastHashOidArc = 0x04;
		digestLen = 28;
		break;
	case CKM_SHA512_224:
		lastHashOidArc = 0x05;
		digestLen = 28;
		break;
	case CKM_SHA512_256:
		lastHashOidArc = 0x06;
		digestLen = 32;
		break;
	case CKM_SHA3_224:
		lastHashOidArc = 0x07;
		digestLen = 28;
		break;
	case CKM_SHA3_256:
		lastHashOidArc = 0x08;
		digestLen = 32;
		break;
	case CKM_SHA3_384:
		lastHashOidArc = 0x09;
		digestLen = 48;
		break;
	case CKM_SHA3_512:
		lastHashOidArc = 0x0A;
		digestLen = 64;
		break;
	// FIPS 205 supports SHAKE128 and SHAKE256 as approved XOFs algorithms for pre-hashing.
	// However, PKCS#11 v3.2 only defines mechanisms for SHAKE key derivation, with no
	// mechanisms for digests. As a result, there is currently no way for a caller to specify
	// that these pre-hash functions were used. This is planned for support in v3.3 or later.
	//
	// See: https://groups.oasis-open.org/discussion/questions-about-the-hash-ml-dsa-signature-and-hash-slh-dsa-signature
	case CKM_SHAKE_128_KEY_DERIVE:
	case CKM_SHAKE_256_KEY_DERIVE:
		ERROR_MSG("SLH-DSA: Invalid parameters, SHAKE pre-hash mechanisms are unsupported in PKCS#11 v3.2.");
		return CKR_MECHANISM_PARAM_INVALID;
	default:
		ERROR_MSG("SLH-DSA: Invalid parameters, unsupported pre-hash mechanism (0x%08lX)", (unsigned long)inHash);
		return CKR_MECHANISM_PARAM_INVALID;
	}

	const unsigned char oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, lastHashOidArc };
	outOid->resize(sizeof(oid));
	memcpy(&(*outOid)[0], oid, sizeof(oid));
	*outDigestLen = digestLen;

	return CKR_OK;
}

#endif