#!/usr/bin/env python3
"""
Standalone test for llm_enricher.py using only standard library
No external dependencies required beyond what's already installed
"""

import sys
import json
from unittest.mock import Mock, patch, MagicMock

# Mock groq module before importing llm_enricher
sys.modules['groq'] = MagicMock()
sys.modules['dotenv'] = MagicMock()

# Add backend to path
sys.path.insert(0, '../backend')

# Import after mocking dependencies
from llm_enricher import enrich_findings, CACHE

def run_tests():
    print("=" * 70)
    print("TESTING llm_enricher.py - STANDALONE TEST SUITE")
    print("=" * 70)
    
    test_count = 0
    passed = 0
    failed = 0
    
    # Test 1: Basic enrichment
    test_count += 1
    print(f"\n[TEST {test_count}] Basic enrichment with valid findings")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_response = MagicMock()
            mock_response.choices[0].message.content = json.dumps({
                "risk_explanation": "RSA is vulnerable to quantum attacks. Migration is urgent.",
                "migration_recommendation": "Use ML-KEM (Kyber) as replacement.",
                "nist_standard": "ML-KEM",
                "urgency": "high"
            })
            mock_client.chat.completions.create.return_value = mock_response
            
            findings = [
                {"algorithm": "RSA", "classification": "asymmetric"},
                {"algorithm": "RSA", "classification": "asymmetric"}
            ]
            
            result = enrich_findings(findings)
            
            assert "RSA" in result, "RSA not in result"
            assert result["RSA"]["urgency"] == "high", f"Expected urgency 'high', got {result['RSA']['urgency']}"
            assert "ML-KEM" in result["RSA"]["nist_standard"], "ML-KEM not in nist_standard"
            assert mock_client.chat.completions.create.call_count == 1, f"Expected 1 API call, got {mock_client.chat.completions.create.call_count}"
            
            print("✓ PASSED - Enrichment works correctly, caching prevents duplicate calls")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 2: Multiple algorithms
    test_count += 1
    print(f"\n[TEST {test_count}] Multiple different algorithms")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_response1 = MagicMock()
            mock_response1.choices[0].message.content = json.dumps({
                "risk_explanation": "Test RSA",
                "migration_recommendation": "Use ML-KEM",
                "nist_standard": "ML-KEM",
                "urgency": "high"
            })
            
            mock_response2 = MagicMock()
            mock_response2.choices[0].message.content = json.dumps({
                "risk_explanation": "Test SHA1",
                "migration_recommendation": "Use SHA-256",
                "nist_standard": "SHA-256",
                "urgency": "critical"
            })
            
            mock_client.chat.completions.create.side_effect = [mock_response1, mock_response2]
            
            findings = [
                {"algorithm": "RSA", "classification": "asymmetric"},
                {"algorithm": "SHA1", "classification": "hash"}
            ]
            
            result = enrich_findings(findings)
            
            assert "RSA" in result, "RSA not in result"
            assert "SHA1" in result, "SHA1 not in result"
            assert result["RSA"]["urgency"] == "high", f"RSA urgency mismatch"
            assert result["SHA1"]["urgency"] == "critical", f"SHA1 urgency mismatch"
            assert mock_client.chat.completions.create.call_count == 2, f"Expected 2 API calls, got {mock_client.chat.completions.create.call_count}"
            
            print("✓ PASSED - Multiple algorithms enriched independently")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 3: Markdown stripping
    test_count += 1
    print(f"\n[TEST {test_count}] Markdown formatting stripped from API response")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_response = MagicMock()
            mock_response.choices[0].message.content = "```json\n" + json.dumps({
                "risk_explanation": "Test",
                "migration_recommendation": "Test recommendation",
                "nist_standard": "Test standard",
                "urgency": "medium"
            }) + "\n```"
            mock_client.chat.completions.create.return_value = mock_response
            
            findings = [{"algorithm": "ECC", "classification": "asymmetric"}]
            
            result = enrich_findings(findings)
            
            assert "ECC" in result, "ECC not in result"
            assert result["ECC"]["urgency"] == "medium", f"Expected urgency 'medium', got {result['ECC']['urgency']}"
            
            print("✓ PASSED - Markdown code blocks properly stripped")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 4: API Error Fallback
    test_count += 1
    print(f"\n[TEST {test_count}] Fallback when API call fails")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_client.chat.completions.create.side_effect = Exception("API Error")
            
            findings = [{"algorithm": "RSA", "classification": "asymmetric"}]
            
            result = enrich_findings(findings)
            
            assert "RSA" in result, "RSA not in result"
            assert result["RSA"]["risk_explanation"] == "Analysis unavailable.", f"Fallback message mismatch"
            assert result["RSA"]["urgency"] == "high", f"Fallback urgency mismatch"
            
            print("✓ PASSED - Proper error handling with fallback values")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 5: Cache functionality
    test_count += 1
    print(f"\n[TEST {test_count}] Cache prevents redundant API calls")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_response = MagicMock()
            mock_response.choices[0].message.content = json.dumps({
                "risk_explanation": "Cached result",
                "migration_recommendation": "Use new algo",
                "nist_standard": "NewAlgo",
                "urgency": "high"
            })
            mock_client.chat.completions.create.return_value = mock_response
            
            findings1 = [{"algorithm": "AES", "classification": "symmetric"}]
            result1 = enrich_findings(findings1)
            
            findings2 = [{"algorithm": "AES", "classification": "symmetric"}]
            result2 = enrich_findings(findings2)
            
            assert mock_client.chat.completions.create.call_count == 1, f"Cache not working - expected 1 call, got {mock_client.chat.completions.create.call_count}"
            assert result1["AES"] == result2["AES"], "Cached results don't match"
            
            print("✓ PASSED - Cache correctly prevents duplicate API calls")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 6: Empty findings
    test_count += 1
    print(f"\n[TEST {test_count}] Empty findings list")
    try:
        CACHE.clear()
        result = enrich_findings([])
        assert result == {}, f"Expected empty dict, got {result}"
        
        print("✓ PASSED - Empty findings handled correctly")
        passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 7: Missing algorithm field
    test_count += 1
    print(f"\n[TEST {test_count}] Missing algorithm field in findings")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_response = MagicMock()
            mock_response.choices[0].message.content = json.dumps({
                "risk_explanation": "Test",
                "migration_recommendation": "Test",
                "nist_standard": "Test",
                "urgency": "high"
            })
            mock_client.chat.completions.create.return_value = mock_response
            
            findings = [
                {"classification": "symmetric"},  # Missing algorithm - should be skipped
                {"algorithm": "AES", "classification": "symmetric"}  # Has algorithm - should be processed
            ]
            
            result = enrich_findings(findings)
            
            # Only AES should be in result (first item lacks algorithm field)
            assert "AES" in result, "AES should be in result"
            assert len(result) == 1, f"Expected 1 result, got {len(result)}"
            
            print("✓ PASSED - Findings without algorithm field skipped correctly")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Test 8: Invalid JSON response
    test_count += 1
    print(f"\n[TEST {test_count}] Invalid JSON response from API")
    try:
        CACHE.clear()
        with patch('llm_enricher.client') as mock_client:
            mock_response = MagicMock()
            mock_response.choices[0].message.content = "Not valid JSON"
            mock_client.chat.completions.create.return_value = mock_response
            
            findings = [{"algorithm": "RSA", "classification": "asymmetric"}]
            
            result = enrich_findings(findings)
            
            assert "RSA" in result, "RSA not in result"
            assert result["RSA"]["risk_explanation"] == "Analysis unavailable.", "Fallback not used for invalid JSON"
            
            print("✓ PASSED - Invalid JSON responses fallback correctly")
            passed += 1
    except Exception as e:
        print(f"✗ FAILED - {str(e)}")
        failed += 1

    # Print summary
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed out of {test_count} tests")
    print("=" * 70)
    
    if failed == 0:
        print("✓ ALL TESTS PASSED - llm_enricher.py is working properly!")
        return True
    else:
        print("✗ SOME TESTS FAILED - Review the output above")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
