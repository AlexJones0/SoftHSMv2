/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 SLHDSATests.h

 Contains test cases to test the SLH-DSA class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSATESTS_H
#define _SOFTHSM_V2_SLHDSATESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class SLHDSATests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(SLHDSATests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testSigningVerifying);
	CPPUNIT_TEST(testSigningVerifyingPreHashed);

	CPPUNIT_TEST(testSigningVerifyingHedgePreferred);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredWithContext);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredPreHashedWithContext);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredPreHashed);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredPreHashedWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequired);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredWithContext);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredPreHashed);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredPreHashedWithContext);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredPreHashedWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingDeterministic);
	CPPUNIT_TEST(testSigningVerifyingDeterministicWithContext);
	CPPUNIT_TEST(testSigningVerifyingDeterministicWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingDeterministicPreHashed);
	CPPUNIT_TEST(testSigningVerifyingDeterministicPreHashedWithContext);
	CPPUNIT_TEST(testSigningVerifyingDeterministicPreHashedWithContextTooLong);
	CPPUNIT_TEST_SUITE_END();

public:
	SLHDSATests();

	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testSigningVerifying();
	void testSigningVerifyingPreHashed();

	void testSigningVerifyingHedgePreferred();
	void testSigningVerifyingHedgePreferredWithContext();
	void testSigningVerifyingHedgePreferredWithContextTooLong();
	void testSigningVerifyingHedgePreferredPreHashed();
	void testSigningVerifyingHedgePreferredPreHashedWithContext();
	void testSigningVerifyingHedgePreferredPreHashedWithContextTooLong();
	void testSigningVerifyingHedgeRequired();
	void testSigningVerifyingHedgeRequiredWithContext();
	void testSigningVerifyingHedgeRequiredWithContextTooLong();
	void testSigningVerifyingHedgeRequiredPreHashed();
	void testSigningVerifyingHedgeRequiredPreHashedWithContext();
	void testSigningVerifyingHedgeRequiredPreHashedWithContextTooLong();
	void testSigningVerifyingDeterministic();
	void testSigningVerifyingDeterministicWithContext();
	void testSigningVerifyingDeterministicWithContextTooLong();
	void testSigningVerifyingDeterministicPreHashed();
	void testSigningVerifyingDeterministicPreHashedWithContext();
	void testSigningVerifyingDeterministicPreHashedWithContextTooLong();

	void setUp();
	void tearDown();

private:
	// SLHDSA instance
	AsymmetricAlgorithm* slhdsa;
};

#endif // !_SOFTHSM_V2_SLHDSATESTS_H

